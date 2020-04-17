use std::{f32, net::Ipv4Addr, time::Duration};

use pnet::packet::{
    icmp::{
        self,
        echo_request::{EchoRequestPacket, MutableEchoRequestPacket},
        IcmpCode, IcmpTypes, MutableIcmpPacket,
    },
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
};

const IPV4_HEADER_SIZE: usize = Ipv4Packet::minimum_packet_size();
const IPV4_HEADER_LEN: u8 = IPV4_HEADER_SIZE as u8 / 4;
const ICMP_HEADER_SIZE: usize = EchoRequestPacket::minimum_packet_size();
pub const TOTAL_HEADER_SIZE: usize = IPV4_HEADER_SIZE + ICMP_HEADER_SIZE;

pub struct PacketBuilder {
    ttl: u8,
    id: u16,
    seq: u16,
    payload_size: usize,
    dest: Ipv4Addr,
}

impl PacketBuilder {
    pub fn new(ttl: u8, id: u16, payload_size: usize, dest: Ipv4Addr) -> Self {
        Self {
            ttl,
            id,
            seq: 1,
            payload_size,
            dest,
        }
    }

    /// Gets an ICMP request with the current pinger parameters.
    pub fn get_packet(&mut self) -> (u16, MutableIpv4Packet<'static>) {
        let ip_payload_size = ICMP_HEADER_SIZE + self.payload_size;
        let packet_size = IPV4_HEADER_SIZE + ip_payload_size;

        let seq = self.seq;
        let mut ip_payload = vec![0u8; ip_payload_size];
        // Set ICMP Headers
        {
            let mut echo_req = MutableEchoRequestPacket::new(&mut ip_payload).unwrap();
            echo_req.set_icmp_type(IcmpTypes::EchoRequest);
            echo_req.set_icmp_code(IcmpCode::new(0));
            echo_req.set_identifier(self.id);
            echo_req.set_sequence_number(seq);
        }
        // Set ICMP Checksum
        {
            let mut icmp_packet = MutableIcmpPacket::new(&mut ip_payload).unwrap();
            let checksum = icmp::checksum(&icmp_packet.to_immutable());
            icmp_packet.set_checksum(checksum);
        }
        // Create the final packet
        let packet = vec![0u8; packet_size];
        let mut ipv4 = MutableIpv4Packet::owned(packet).unwrap();
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ipv4.set_header_length(IPV4_HEADER_LEN);
        ipv4.set_total_length(packet_size as u16);
        ipv4.set_payload(&ip_payload);
        ipv4.set_version(4);
        ipv4.set_ttl(self.ttl);
        ipv4.set_destination(self.dest);
        ipv4.set_flags(Ipv4Flags::DontFragment);
        ipv4.set_options(&[]);

        self.seq += 1;

        (seq, ipv4)
    }
}

#[derive(Default)]
pub struct TimeStats {
    min: f32,    // Minimum time
    max: f32,    // Maximum time
    sum: f32,    // Sum of times
    sq_sum: f32, // Sum of squared times
    sent: usize, // Number of packets sent
    lost: usize, // Number of packets lost
    recv: usize, // Number of packets received
}

impl TimeStats {
    pub fn new() -> Self {
        Self {
            min: f32::INFINITY,
            max: f32::NEG_INFINITY,
            sum: 0.0,
            sq_sum: 0.0,
            sent: 0,
            lost: 0,
            recv: 0,
        }
    }

    pub fn recv(&mut self, time: f32) {
        if time < self.min {
            self.min = time;
        }

        if time > self.max {
            self.max = time;
        }

        self.sum += time;
        self.sq_sum += time.powi(2);
        self.recv += 1;
    }

    pub fn sent(&mut self) {
        self.sent += 1;
    }

    pub fn lost(&mut self) {
        self.lost += 1;
    }

    pub fn num_sent(&self) -> usize {
        self.sent
    }

    pub fn num_lost(&self) -> usize {
        self.lost
    }

    pub fn num_recv(&self) -> usize {
        self.recv
    }

    pub fn min(&self) -> f32 {
        self.min
    }

    pub fn max(&self) -> f32 {
        self.max
    }

    pub fn avg(&self) -> f32 {
        self.sum / self.recv as f32
    }

    pub fn std(&self) -> f32 {
        ((self.sq_sum / self.recv as f32) - self.avg().powi(2)).sqrt()
    }

    pub fn loss_pct(&self) -> f32 {
        100.0 * (1.0 - self.num_recv() as f32 / self.num_sent() as f32)
    }

    pub fn print_summary(&self) {
        println!("Summary:");
        println!("  Min: {:#.2?}", Duration::from_secs_f32(self.min()));
        println!("  Max: {:#.2?}", Duration::from_secs_f32(self.max()));
        println!("  Avg: {:#.2?}", Duration::from_secs_f32(self.avg()));
        println!("  Std: {:#.2?}", Duration::from_secs_f32(self.std()));
    }
}
