//! Ethernet/IPv4 frame builders shared by demo mode and tests.

use etherparse::PacketBuilder;

const MAC_LOCAL: [u8; 6] = [0x02, 0x00, 0x5E, 0x10, 0x00, 0x01];
const MAC_GATEWAY: [u8; 6] = [0x02, 0x00, 0x5E, 0x10, 0x00, 0xFE];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpFlags {
    Syn,
    SynAck,
    /// PSH + ACK with payload.
    Data,
    Ack,
    Fin,
}

pub fn udp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ethernet2(MAC_LOCAL, MAC_GATEWAY).ipv4(src, dst, 64).udp(sport, dport);
    let mut out = Vec::with_capacity(b.size(payload.len()));
    // Writing into a Vec only fails for oversized payloads, which callers never pass.
    if b.write(&mut out, payload).is_err() {
        out.clear();
    }
    out
}

pub fn tcp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: TcpFlags, payload: &[u8]) -> Vec<u8> {
    tcp_frame_seq(src, dst, sport, dport, flags, u32::from(sport) << 8 | payload.len() as u32, payload)
}

/// Like [`tcp_frame`] with an explicit sequence number (for realistic streams).
pub fn tcp_frame_seq(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: TcpFlags, seq: u32, payload: &[u8]) -> Vec<u8> {
    let base = PacketBuilder::ethernet2(MAC_LOCAL, MAC_GATEWAY).ipv4(src, dst, 64).tcp(sport, dport, seq, 64_240);
    let b = match flags {
        TcpFlags::Syn => base.syn(),
        TcpFlags::SynAck => base.syn().ack(1),
        TcpFlags::Data => base.psh().ack(1),
        TcpFlags::Ack => base.ack(1),
        TcpFlags::Fin => base.fin().ack(1),
    };
    let mut out = Vec::with_capacity(b.size(payload.len()));
    if b.write(&mut out, payload).is_err() {
        out.clear();
    }
    out
}
