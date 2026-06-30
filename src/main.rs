//! DIG Relay — NAT-traversal rendezvous + circuit relay for the DIG Network.
//!
//! DIG Nodes behind NAT can't always dial each other directly. The relay is a
//! well-known, publicly-reachable rendezvous point (default `relay.dig.net`) that
//! lets nodes discover peers and bridge connections: peers register, attempt
//! hole-punching, and fall back to relayed transport when a direct path can't be
//! established. A DIG Node maintains a constant reservation/connection with the
//! relay so it stays reachable.
//!
//! Scaffold entrypoint — the real relay server (transport, reservations,
//! hole-punch coordination, health endpoint) lands on top of this.

fn main() {
    println!("dig-relay: scaffold. Relay server implementation pending.");
}
