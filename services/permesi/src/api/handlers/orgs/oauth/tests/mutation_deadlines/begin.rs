//! Real PostgreSQL cancellation at the wire-level BEGIN acknowledgement boundary.
//!
//! A fixture-owned TCP relay pauses server replies after a connection is idle.
//! PostgreSQL confirms BEGIN independently before cancellation; no mocked transaction
//! or timing guess can satisfy the later cross-connection session-revocation checks.

use super::*;
use std::{io, net::SocketAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
};

struct ReplyGate {
    address: SocketAddr,
    paused: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl ReplyGate {
    /// Relays only this fixture's PostgreSQL socket; owns and aborts every relay task.
    async fn start(pool: &PgPool) -> Result<Self> {
        let upstream = pool.connect_options();
        let host = upstream.get_host().to_owned();
        let port = upstream.get_port();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (paused, receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((client, _)) = accepted else { return };
                        let host = host.clone();
                        let receiver = receiver.clone();
                        children.spawn(async move {
                            let server = TcpStream::connect((host.as_str(), port)).await?;
                            relay(client, server, receiver).await
                        });
                    }
                    Some(_) = children.join_next(), if !children.is_empty() => {}
                }
            }
        });
        Ok(Self {
            address,
            paused,
            task,
        })
    }
}

impl Drop for ReplyGate {
    /// Closing the accept task also drops its `JoinSet` and all owned socket relays.
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Leaves client commands unchanged while optionally withholding all server acknowledgements.
async fn relay(
    client: TcpStream,
    server: TcpStream,
    paused: watch::Receiver<bool>,
) -> io::Result<()> {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let requests = tokio::io::copy(&mut client_read, &mut server_write);
    let replies = async move {
        let mut paused = paused;
        let mut bytes = [0u8; 8192];
        loop {
            let count = server_read.read(&mut bytes).await?;
            if count == 0 {
                return Ok::<_, io::Error>(());
            }
            paused
                .wait_for(|paused| !*paused)
                .await
                .map_err(io::Error::other)?;
            let chunk = bytes
                .get(..count)
                .ok_or_else(|| io::Error::other("Invalid fixture reply length"))?;
            client_write.write_all(chunk).await?;
        }
    };
    tokio::select! {
        result = requests => result.map(|_| ()),
        result = replies => result,
    }
}

/// Requires a returned connection rather than guessing when asynchronous pool cleanup finished.
async fn idle(pool: &PgPool) -> Result<()> {
    timeout(Duration::from_secs(3), async {
        while pool.num_idle() != 1 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .context("Cancelled BEGIN did not return its connection")
}

/// Waits for the actual server transaction while its acknowledgement remains withheld.
async fn server_transaction(pool: &PgPool, pid: i32) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND state='idle in transaction')",
    )
    .bind(pid)
    .fetch_one(pool)
    .await?)
}

/// Exercises a real acknowledgement-boundary cancellation through either shared caller.
async fn cancelled_begin(auth: bool) -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let gate = ReplyGate::start(&f.db.pool).await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .test_before_acquire(false)
        .connect_with(
            f.db.pool
                .connect_options()
                .as_ref()
                .clone()
                .host("127.0.0.1")
                .port(gate.address.port()),
        )
        .await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await?;
    idle(&pool).await?;
    gate.paused.send_replace(true);
    let pending_pool = pool.clone();
    let operation = tokio::spawn(async move {
        let transaction = if auth {
            crate::api::handlers::auth::operations::begin(&pending_pool, 2000).await?
        } else {
            MutationPolicy::new(50, 2000, 16)?
                .begin(&pending_pool)
                .await?
        };
        drop(transaction);
        Ok::<_, anyhow::Error>(())
    });
    timeout(Duration::from_secs(3), async {
        while !server_transaction(&f.db.pool, pid).await? {
            sleep(Duration::from_millis(5)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    operation.abort();
    assert!(operation.await.is_err_and(|error| error.is_cancelled()));
    gate.paused.send_replace(false);
    idle(&pool).await?;
    let leaked = server_transaction(&f.db.pool, pid).await?;
    sqlx::query("DELETE FROM user_sessions WHERE user_id=$1")
        .bind(f.owner)
        .execute(&pool)
        .await?;
    let visible: bool =
        sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM user_sessions WHERE user_id=$1)")
            .bind(f.owner)
            .fetch_one(&f.db.pool)
            .await?;
    if leaked {
        sqlx::query("ROLLBACK").execute(&pool).await?;
    }
    pool.close().await;
    assert!(
        !leaked,
        "Cancelled BEGIN returned an open server transaction to the pool"
    );
    assert!(
        visible,
        "Later session revocation was not committed across connections"
    );
    Ok(())
}

/// Neither tenant nor authentication BEGIN cancellation can absorb a later session revocation.
#[tokio::test]
async fn tenant_mutation_cancelled_begin_cannot_leak_into_later_autocommit() -> Result<()> {
    cancelled_begin(false).await?;
    cancelled_begin(true).await
}
