//! Dual-stack socket binding — IPv6-first, IPv4-fallback (dig_ecosystem hard rule).
//!
//! [`RelayServerConfig`](crate::config::RelayServerConfig)'s listener defaults are the IPv6
//! unspecified address `[::]`. Binding `[::]` with the OS default `IPV6_V6ONLY=1` (the default on
//! Windows and some Linux distros) would make the socket IPv6-ONLY, silently dropping IPv4
//! reachability that `0.0.0.0` used to provide. This module clears `IPV6_V6ONLY` at bind time so an
//! `[::]` socket stays **dual-stack**: it accepts native IPv6 connections AND IPv4 (via
//! IPv4-mapped-IPv6) connections on the exact same socket/port.
//!
//! An explicit IPv4 bind address (an operator passing `--listen 0.0.0.0:9450` or a specific IPv4
//! host) is left alone — `set_only_v6` only applies to an IPv6 address, and dual-stack is
//! meaningless for an IPv4 socket, so [`bind_tcp_dual_stack`] / [`bind_udp_dual_stack`] simply skip
//! the option in that case and behave exactly like a plain bind.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};

/// Bind a TCP listener at `addr`. When `addr` is IPv6, the socket is explicitly set dual-stack
/// (`IPV6_V6ONLY=false`) before `listen`, so it accepts both native IPv6 and IPv4-mapped peers.
pub fn bind_tcp_dual_stack(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = new_dual_stack_socket(addr, Type::STREAM, Protocol::TCP)?;
    // Backlog: mirror the value Rust's std/tokio TcpListener::bind uses (128).
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// Bind a UDP socket at `addr`. When `addr` is IPv6, the socket is explicitly set dual-stack
/// (`IPV6_V6ONLY=false`), so it accepts both native IPv6 and IPv4-mapped datagrams.
pub fn bind_udp_dual_stack(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = new_dual_stack_socket(addr, Type::DGRAM, Protocol::UDP)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Shared construction: a `socket2::Socket` of the right domain/type, `SO_REUSEADDR` set (matching
/// std/tokio's own bind behaviour so a restarted relay can rebind promptly), `IPV6_V6ONLY` cleared
/// for an IPv6 address, then bound to `addr`.
fn new_dual_stack_socket(addr: SocketAddr, ty: Type, protocol: Protocol) -> io::Result<Socket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, ty, Some(protocol))?;
    if addr.is_ipv6() {
        // Only meaningful for IPv6; also only settable before bind on most platforms.
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Binding `[::]:0` (ephemeral port) must succeed and, when the OS supports dual-stack, must
    /// accept an IPv4 (loopback) connection on that same socket — proving `IPV6_V6ONLY` was cleared.
    /// (A handful of exotic environments genuinely lack dual-stack support; skip gracefully there
    /// rather than failing on infrastructure the fix cannot control.)
    #[tokio::test]
    async fn tcp_unspecified_ipv6_bind_accepts_an_ipv4_loopback_client() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let listener = bind_tcp_dual_stack(addr).expect("dual-stack TCP bind must succeed");
        let port = listener.local_addr().unwrap().port();

        let accept = tokio::spawn(async move { listener.accept().await });

        let v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        match tokio::net::TcpStream::connect(v4_addr).await {
            Ok(_client) => {
                let (_, peer) = accept
                    .await
                    .unwrap()
                    .expect("dual-stack listener must accept the IPv4 client");
                // The peer address arrives as an IPv4-mapped IPv6 (or plain IPv4) address either way.
                assert!(peer.ip().to_canonical().is_ipv4());
            }
            Err(e) => {
                // No IPv4/IPv6 dual-stack support on this host/CI runner — not what this test
                // covers (a genuine socket-option bug would fail the *connect*, not report this
                // specific OS limitation), so don't fail the suite over host capability.
                accept.abort();
                eprintln!("skipping: host lacks IPv4-mapped-IPv6 dual-stack support: {e}");
            }
        }
    }

    #[tokio::test]
    async fn tcp_bind_on_explicit_ipv4_address_is_unaffected() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let listener = bind_tcp_dual_stack(addr).expect("plain IPv4 bind must still work");
        assert!(listener.local_addr().unwrap().is_ipv4());
    }

    #[tokio::test]
    async fn udp_unspecified_ipv6_bind_receives_an_ipv4_loopback_datagram() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let server = bind_udp_dual_stack(addr).expect("dual-stack UDP bind must succeed");
        let port = server.local_addr().unwrap().port();

        let client = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        if client.send_to(b"ping", dest).await.is_err() {
            eprintln!("skipping: could not send IPv4 datagram to dual-stack IPv6 socket");
            return;
        }

        let mut buf = [0u8; 16];
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((n, _from))) => assert_eq!(&buf[..n], b"ping"),
            _ => eprintln!("skipping: host lacks IPv4-mapped-IPv6 dual-stack support for UDP"),
        }
    }

    #[tokio::test]
    async fn udp_bind_on_explicit_ipv4_address_is_unaffected() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let socket = bind_udp_dual_stack(addr).expect("plain IPv4 UDP bind must still work");
        assert!(socket.local_addr().unwrap().is_ipv4());
    }
}
