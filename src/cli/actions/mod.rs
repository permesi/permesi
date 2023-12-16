pub mod server;

#[derive(Debug)]
pub enum Action {
    Server { port: u16, dsn: String },
}
