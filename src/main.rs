extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;

use std::env;

fn main() {
    let interface_name = env::args().nth(1).unwrap();

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == interface_name)
        .next()
        .expect("failed to get interface");

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            panic!("failed to create datalink channel {}", e)
        }
    };

    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = EthernetPacket::new(frame).unwrap();
                match ethernet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        ipv4_handler(&frame);
                    },
                    EtherTypes::Ipv6 => {
                        ipv6_handler(&frame);
                    }
                    _ => {
                        println!("not ipv4");
                    }
                }
            },
            Err(e) => {
                panic!("failed to read: {}", e);
            }
        }
    }
}

// fn print_data<T: Packet, U: Packet>(l3: T, l4: U, proto: &str) {
//     println!("Received {} packet {}:{} to {}:{}",
//         proto,
//         l3.get_source(),
//         l4.get_source(),
//         l3.get_destination(),
//         l4.get_destination()
//     );
// }

fn ipv4_handler(ethernet: &EthernetPacket) {
    if let Some(packet) = Ipv4Packet::new(ethernet.payload()){
        match packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                tcp_handler(&packet);
            },
            IpNextHeaderProtocols::Udp => {
                udp_handler(&packet);
            },
            _ => {
                println!("not tcp or udp packet");
            }
        }
    }
}


fn ipv6_handler(ethernet: &EthernetPacket) {
    if let Some(packet) = Ipv6Packet::new(ethernet.payload()){
        match packet.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                tcp_handler(&packet);
            },
            IpNextHeaderProtocols::Udp => {
                udp_handler(&packet);
            },
            _ => {
                println!("not tcp or udp packet");
            }
        }
    }
}

fn tcp_handler(packet: &Packet) {
    let tcp = TcpPacket::new(packet.payload());
    if let Some(tcp) = tcp {
        println!("Received TCP packet {}:{} to {}:{}",
            packet.get_source(),
            tcp.get_source(),
            packet.get_destination(),
            tcp.get_destination()
        );
    }
}

fn udp_handler(packet: &Packet) {
    let udp = UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        println!("Received UDP packet {}:{} to {}:{}",
            packet.get_source(),
            udp.get_source(),
            packet.get_destination(),
            udp.get_destination()
        );
    }
}