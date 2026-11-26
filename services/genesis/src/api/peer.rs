//! Which transport peers may supply forwarded request metadata.
//!
//! Genesis records the client address and country with every token for audit. Behind an
//! edge both arrive in request headers, and a header is only as trustworthy as whoever
//! sent it: a caller that reaches Genesis without the edge can write any address it
//! likes. The policy here ties the headers to the transport peer.
//!
//! ## Flow Overview
//! 1. The listener records the peer: the TCP server attaches `ConnectInfo`, the Unix
//!    socket server attaches the [`UnixPeer`] marker.
//! 2. [`Peer`] reads that from the request; it never looks at a header.
//! 3. [`RequestMetadataPolicy::trusts`] accepts the forwarded headers only from a peer
//!    inside a configured proxy range, or from the same-host proxy on the Unix socket
//!    when that is enabled.
//! 4. For any other peer the headers are ignored and the peer's own address is recorded.
//!
//! The metadata is stored for audit and never decides a request, so an untrusted header
//! is dropped, not rejected.

use anyhow::{Context, Result, ensure};
use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, HeaderName, request::Parts},
};
use sqlx::types::ipnetwork::IpNetwork;
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
};

/// Marker installed only by the Unix listener; a TCP request without peer information
/// does not gain trust by lacking it.
#[derive(Clone, Copy)]
pub struct UnixPeer;

/// The transport peer of a request, taken from what the listener recorded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Peer {
    /// Canonical address of a TCP peer; `None` on the Unix socket.
    pub address: Option<IpAddr>,
    /// The request arrived on the Unix socket.
    pub unix: bool,
}

impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Infallible>> + Send {
        std::future::ready(Ok(Self {
            // A dual-stack listener reports IPv4 peers as IPv4-mapped IPv6 addresses.
            address: parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip().to_canonical()),
            unix: parts.extensions.get::<UnixPeer>().is_some(),
        }))
    }
}

/// Header names for forwarded metadata and the peers allowed to send them.
#[derive(Clone, Debug)]
pub struct RequestMetadataPolicy {
    ip_header: HeaderName,
    country_header: HeaderName,
    trusted_proxies: Vec<IpNetwork>,
    trust_unix_proxy: bool,
}

impl RequestMetadataPolicy {
    /// Build the policy from clap-validated settings, checking the header names again.
    ///
    /// # Errors
    /// Returns an error if either name is not a valid HTTP header name.
    pub fn new(
        ip_header: &str,
        country_header: &str,
        trusted_proxies: Vec<IpNetwork>,
        trust_unix_proxy: bool,
    ) -> Result<Self> {
        let name = |value: &str| {
            ensure!(!value.trim().is_empty(), "header name is empty");
            HeaderName::try_from(value.trim()).context("invalid header name")
        };
        Ok(Self {
            ip_header: name(ip_header).context("invalid client address header")?,
            country_header: name(country_header).context("invalid client country header")?,
            trusted_proxies,
            trust_unix_proxy,
        })
    }

    /// Whether `peer` may supply the forwarded headers: a TCP peer inside a configured
    /// proxy range, or the Unix socket peer when the same-host proxy is trusted. Reads
    /// the transport only, never a header, and has no side effects.
    #[must_use]
    pub fn trusts(&self, peer: Peer) -> bool {
        (peer.unix && self.trust_unix_proxy)
            || peer.address.is_some_and(|address| {
                self.trusted_proxies
                    .iter()
                    .any(|network| network.contains(address))
            })
    }

    /// The client address to record: the forwarded one from a trusted peer, when the
    /// header is present exactly once and parses, and otherwise the peer's own address.
    #[must_use]
    pub fn client_address(&self, peer: Peer, headers: &HeaderMap) -> Option<IpAddr> {
        let forwarded = (self.trusts(peer) && headers.get_all(&self.ip_header).iter().count() == 1)
            .then(|| headers.get(&self.ip_header))
            .flatten()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
            .map(|address| address.to_canonical());
        forwarded.or(peer.address)
    }

    /// The raw country header, only from a trusted peer.
    #[must_use]
    pub fn client_country<'a>(&self, peer: Peer, headers: &'a HeaderMap) -> Option<&'a str> {
        self.trusts(peer)
            .then(|| headers.get(&self.country_header))
            .flatten()
            .and_then(|value| value.to_str().ok())
    }

    /// One-line summary for the startup log; header names and ranges are not secrets.
    #[must_use]
    pub fn summary(&self) -> String {
        let proxies = if self.trusted_proxies.is_empty() {
            "none".to_string()
        } else {
            self.trusted_proxies
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "address={} country={} trusted_proxies={proxies} trust_unix_proxy={}",
            self.ip_header, self.country_header, self.trust_unix_proxy
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn policy(proxies: &[&str], trust_unix_proxy: bool) -> Result<RequestMetadataPolicy> {
        RequestMetadataPolicy::new(
            "CF-Connecting-IP",
            "CF-IPCountry",
            proxies
                .iter()
                .map(|range| range.parse())
                .collect::<Result<_, _>>()?,
            trust_unix_proxy,
        )
    }

    fn tcp(address: &str) -> Result<Peer> {
        Ok(Peer {
            address: Some(address.parse()?),
            unix: false,
        })
    }

    fn forwarded() -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert("CF-Connecting-IP", "198.51.100.7".parse()?);
        headers.insert("CF-IPCountry", "SE".parse()?);
        Ok(headers)
    }

    /// The regression this module exists for: a caller that reaches Genesis directly
    /// cannot choose the address or country that is recorded for it.
    #[test]
    fn untrusted_peer_cannot_supply_address_or_country() -> Result<()> {
        let headers = forwarded()?;
        for (policy, peer) in [
            // No proxy configured at all, the default.
            (policy(&[], false)?, tcp("203.0.113.9")?),
            // A proxy is configured, and the caller is not it.
            (policy(&["192.0.2.0/24"], false)?, tcp("203.0.113.9")?),
            (policy(&["192.0.2.0/24"], true)?, tcp("203.0.113.9")?),
        ] {
            assert!(!policy.trusts(peer));
            assert_eq!(
                policy.client_address(peer, &headers),
                Some("203.0.113.9".parse()?),
                "the transport peer is recorded, not the header"
            );
            assert_eq!(policy.client_country(peer, &headers), None);
        }
        Ok(())
    }

    #[test]
    fn trusted_proxy_supplies_address_and_country() -> Result<()> {
        let policy = policy(&["192.0.2.0/24", "2001:db8::/32"], false)?;
        let headers = forwarded()?;
        for peer in [tcp("192.0.2.10")?, tcp("2001:db8::10")?] {
            assert!(policy.trusts(peer));
            assert_eq!(
                policy.client_address(peer, &headers),
                Some("198.51.100.7".parse()?)
            );
            assert_eq!(policy.client_country(peer, &headers), Some("SE"));
        }
        Ok(())
    }

    /// A trusted proxy that sends no usable address, or more than one, is recorded as
    /// itself: two values mean something upstream appended instead of overwriting.
    #[test]
    fn trusted_proxy_without_one_parsable_address_is_recorded_as_itself() -> Result<()> {
        let policy = policy(&["192.0.2.0/24"], false)?;
        let peer = tcp("192.0.2.10")?;
        let mut twice = HeaderMap::new();
        twice.append("CF-Connecting-IP", "198.51.100.7".parse()?);
        twice.append("CF-Connecting-IP", "198.51.100.8".parse()?);
        let mut garbage = HeaderMap::new();
        garbage.insert("CF-Connecting-IP", "not-an-address".parse()?);
        for headers in [HeaderMap::new(), twice, garbage] {
            assert_eq!(
                policy.client_address(peer, &headers),
                Some("192.0.2.10".parse()?)
            );
        }
        Ok(())
    }

    #[test]
    fn unix_socket_peer_is_trusted_only_when_enabled() -> Result<()> {
        let headers = forwarded()?;
        let unix = Peer {
            address: None,
            unix: true,
        };
        let enabled = policy(&[], true)?;
        assert!(enabled.trusts(unix));
        assert_eq!(
            enabled.client_address(unix, &headers),
            Some("198.51.100.7".parse()?)
        );
        assert_eq!(enabled.client_country(unix, &headers), Some("SE"));

        let disabled = policy(&["192.0.2.0/24"], false)?;
        assert!(!disabled.trusts(unix));
        assert_eq!(disabled.client_address(unix, &headers), None);
        assert_eq!(disabled.client_country(unix, &headers), None);

        // A request with no recorded peer at all is not the Unix proxy.
        assert!(!enabled.trusts(Peer::default()));
        assert_eq!(enabled.client_address(Peer::default(), &headers), None);
        Ok(())
    }

    #[test]
    fn configured_header_names_replace_the_defaults() -> Result<()> {
        let policy = RequestMetadataPolicy::new(
            "X-Real-IP",
            "X-Country",
            vec!["192.0.2.0/24".parse()?],
            false,
        )?;
        let peer = tcp("192.0.2.10")?;
        let mut headers = forwarded()?;
        assert_eq!(
            policy.client_address(peer, &headers),
            Some("192.0.2.10".parse()?),
            "the default header is no longer read"
        );
        headers.insert("X-Real-IP", "198.51.100.99".parse()?);
        headers.insert("X-Country", "NO".parse()?);
        assert_eq!(
            policy.client_address(peer, &headers),
            Some("198.51.100.99".parse()?)
        );
        assert_eq!(policy.client_country(peer, &headers), Some("NO"));
        Ok(())
    }

    #[test]
    fn header_names_are_validated() {
        for (address, country) in [("", "CF-IPCountry"), ("bad name", "CF-IPCountry")] {
            assert!(RequestMetadataPolicy::new(address, country, Vec::new(), false).is_err());
            assert!(RequestMetadataPolicy::new(country, address, Vec::new(), false).is_err());
        }
    }

    /// The extractor reads what the listener recorded and nothing a caller can send. An
    /// IPv4 peer on a dual-stack listener arrives IPv4-mapped and has to match an IPv4
    /// proxy range.
    #[tokio::test]
    async fn peer_comes_from_the_listener_and_matches_ipv4_ranges_on_dual_stack() -> Result<()> {
        let parts = || -> Result<Parts> {
            let request = Request::builder()
                .uri("/")
                .header("CF-Connecting-IP", "198.51.100.7")
                .header("X-Real-IP", "198.51.100.7")
                .body(())?;
            Ok(request.into_parts().0)
        };
        let peer = |mut parts: Parts| async move {
            let Ok(peer) = Peer::from_request_parts(&mut parts, &()).await;
            peer
        };

        assert_eq!(peer(parts()?).await, Peer::default());

        let mut mapped = parts()?;
        mapped.extensions.insert(ConnectInfo(
            "[::ffff:192.0.2.10]:4000".parse::<SocketAddr>()?,
        ));
        let mapped = peer(mapped).await;
        assert_eq!(mapped, tcp("192.0.2.10")?);
        assert!(policy(&["192.0.2.0/24"], false)?.trusts(mapped));

        let mut unix = parts()?;
        unix.extensions.insert(UnixPeer);
        assert_eq!(
            peer(unix).await,
            Peer {
                address: None,
                unix: true
            }
        );
        Ok(())
    }
}
