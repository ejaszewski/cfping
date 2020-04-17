use cfping::*;

use std::{
    collections::HashMap,
    net::*,
    process,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use pnet::{
    packet::{
        icmp::{
            echo_reply::EchoReplyPacket, echo_request::EchoRequestPacket,
            time_exceeded::TimeExceededPacket, IcmpPacket, IcmpTypes,
        },
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        Packet,
    },
    transport::{ipv4_packet_iter, transport_channel, TransportChannelType::Layer3},
};

use dns_lookup::lookup_host;
use signal_hook;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "cfping")]
struct Opt {
    /// Set IP time to live.
    #[structopt(short, long)]
    ttl: Option<u8>,

    /// The size of the ICMP payload. Defaults to 56 bytes, which sends a packet with total size 64 bytes.
    #[structopt(short, long)]
    size: Option<usize>,

    /// Set the interval of requests sent, in seconds. Defaults to 1 second.
    #[structopt(short, long)]
    interval: Option<f32>,

    #[structopt(name = "DESTINATION")]
    destination: String,
}

fn main() {
    let opt = Opt::from_args();
    let ttl = opt.ttl.unwrap_or(64);
    let payload_size = opt.size.unwrap_or(56);
    let interval = opt.interval.unwrap_or(1.0);

    // Lookup the IP addresses associated with a name.
    let response = lookup_host(&opt.destination).expect("Unable to resolve hostname.");
    let addr = *response
        .iter()
        .find(|&addr| addr.is_ipv4())
        .expect("Unable to resolve host to IPv4 address.");

    let dst = if let IpAddr::V4(dst) = addr {
        dst
    } else {
        unreachable!() // At this point, addr must be a V4.
    };

    println!(
        "Pinging {} ({}) with {} ({}) bytes of data.",
        opt.destination,
        dst,
        payload_size,
        payload_size + TOTAL_HEADER_SIZE
    );

    // Set up the packet builder
    let id = process::id() as u16; // We want to truncate here, the full id doesn't matter.
    let mut packet_builder = PacketBuilder::new(ttl, id, payload_size, dst);

    // Stores ping statistics (calculated online).
    let ping_stats = Arc::new(Mutex::new(TimeStats::new()));

    // Stores ping times locally (maps seq -> instant).
    let ping_times: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    // Set up the tx and rx channels we'll use later.
    let protocol = Layer3(IpNextHeaderProtocols::Icmp);
    let (mut tx, mut rx) =
        transport_channel(4096, protocol).expect("Unable to construct transport channels.");

    // Set up Ctrl+C handler to print stats
    let sigint_stats = ping_stats.clone();
    unsafe {
        signal_hook::register(signal_hook::SIGINT, move || {
            let stats = sigint_stats.lock().expect("Stats mutex poisoned.");

            println!();
            println!("Ping Statistics:");
            println!("  Transmitted: {}", stats.num_sent());
            println!("  Received   : {}", stats.num_recv());
            println!("  Packet Loss: {:.1}%", stats.loss_pct());

            if stats.num_recv() > 0 {
                stats.print_summary();
            }
            process::exit(0)
        })
    }
    .expect("Unable to register sigint handler.");

    // Start a thread that will spawn packets.
    let send_stats = ping_stats.clone();
    let send_ping_starts = ping_times.clone();
    let _ = thread::spawn(move || loop {
        let (seq, packet) = packet_builder.get_packet();
        let total: usize = packet.get_total_length().into();

        {
            let mut starts = send_ping_starts.lock().expect("Map mutex poisoned.");
            starts.insert(seq, Instant::now());

            let mut stats = send_stats.lock().expect("Stats mutex poisoned");
            stats.sent();
        }

        if let Ok(written) = tx.send_to(packet, addr) {
            if total != written {
                eprintln!("Partial write {} of {} bytes.", written, total);
            }
        } else {
            eprintln!("Failed to send packet.");
        }

        thread::sleep(Duration::from_secs_f32(interval));
    });

    // Start receiving packets.
    let recv_stats = ping_stats;
    let recv_ping_starts = ping_times;
    let mut iter = ipv4_packet_iter(&mut rx);
    loop {
        let res = iter.next();
        match res {
            Err(e) => {
                println!("Error receiving packet: {}", e);
            }
            Ok((ipv4, addr)) => {
                // We only care about ICMP packets.
                if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
                    continue;
                }

                let icmp = IcmpPacket::new(ipv4.payload()).expect("Bad ICMP packet!");
                match icmp.get_icmp_type() {
                    IcmpTypes::TimeExceeded => {
                        let exceeded = TimeExceededPacket::new(ipv4.payload())
                            .expect("Bad Time Exceeded packet");
                        let ipv4_sub = Ipv4Packet::new(exceeded.payload())
                            .expect("Bad Time Exceeded packet");
                        if let Some(echo_req) = EchoRequestPacket::new(ipv4_sub.payload()) {
                            if echo_req.get_identifier() == id {
                                let seq = &echo_req.get_sequence_number();
                                print!("Time exceeded: icmp_seq={}", seq);
                                let mut times =
                                    recv_ping_starts.lock().expect("Map mutex poisoned.");
                                if times.remove(&seq).is_some() {
                                    let mut stats =
                                        recv_stats.lock().expect("Stats mutex poisoned.");
                                    stats.lost();
                                    print!(" loss={:.1}%", stats.loss_pct());
                                }
                                println!();
                            }
                        }
                    }
                    IcmpTypes::EchoReply => {
                        let reply = EchoReplyPacket::new(ipv4.payload())
                            .expect("Bad Echo Reply packet");
                        if reply.get_identifier() == id {
                            let received = Instant::now();
                            let seq = reply.get_sequence_number();

                            let start = {
                                let mut times =
                                    recv_ping_starts.lock().expect("Map mutex poisoned.");
                                match times.remove(&seq) {
                                    Some(time) => time,
                                    None => {
                                        println!("Unexpected sequence number {}.", seq);
                                        continue;
                                    }
                                }
                            };

                            let taken = received - start;

                            print!("{} bytes from {}: ", ipv4.get_total_length(), addr);
                            print!(
                                "icmp_seq={} ttl={} time={:#.2?}",
                                reply.get_sequence_number(),
                                ipv4.get_ttl(),
                                taken
                            );

                            // Insert new time into the stats.
                            {
                                let mut stats =
                                    recv_stats.lock().expect("Stats mutex poisoned.");
                                stats.recv(taken.as_secs_f32());
                                print!(" loss={:.1}%", stats.loss_pct());
                            }

                            println!();
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
