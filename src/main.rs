extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
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
                match frame.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        ipv4_handler(&frame);
                    },
                    EtherTypes::Ipv6 => {
                        ipv6_handler(&frame);
                    }
                    _ => {
                        println!("not ipv4 or ipv6");
                    }
                }
            },
            Err(e) => {
                panic!("failed to read: {}", e);
            }
        }
    }
}

fn print_data(l3: &GettableEndPoints, l4: &GettableEndPoints, proto: &str) {
    println!("Received {} packet {}:{} to {}:{}",
        proto,
        l3.get_source(),
        l4.get_source(),
        l3.get_destination(),
        l4.get_destination()
    );
}

trait GettableEndPoints {
    fn get_source(&self) -> String;
    fn get_destination(&self) -> String;
    fn get_payload(&self) -> &[u8];
}

impl<'a> GettableEndPoints for Ipv4Packet<'a> {
    fn get_source(&self) -> String {
        self.get_source().to_string()
    }

    fn get_destination(&self) -> String {
        self.get_destination().to_string()
    }

    fn get_payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> GettableEndPoints for Ipv6Packet<'a> {
    fn get_source(&self) -> String {
        self.get_source().to_string()
    }

    fn get_destination(&self) -> String {
        self.get_destination().to_string()
    }

    fn get_payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> GettableEndPoints for TcpPacket<'a> {
    fn get_source(&self) -> String {
        self.get_source().to_string()
    }

    fn get_destination(&self) -> String {
        self.get_destination().to_string()
    }

    fn get_payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> GettableEndPoints for UdpPacket<'a> {
    fn get_source(&self) -> String {
        self.get_source().to_string()
    }

    fn get_destination(&self) -> String {
        self.get_destination().to_string()
    }

    fn get_payload(&self) -> &[u8] {
        self.payload()
    }
}


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

fn tcp_handler(packet: &GettableEndPoints) {
    let tcp = TcpPacket::new(packet.get_payload());
    if let Some(tcp) = tcp {
        print_data(packet, &tcp, "TCP");
    }
}

fn udp_handler(packet: &GettableEndPoints) {
    let udp = UdpPacket::new(packet.get_payload());
    if let Some(udp) = udp {
        print_data(packet, &udp, "UDP");
    }
}