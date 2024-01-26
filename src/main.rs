extern crate pcap;
extern crate pnet;
extern crate notify_rust;

use notify_rust::Notification;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

//Right now this code handles the TCP and UDP protocol connections

fn main() {
    let interface = "ens33";

    let mut cap = pcap::Capture::from_device(interface)
        .unwrap()
        .promisc(true)
        .snaplen(5000)
        .open()
        .unwrap();

    while let Ok(packet) = cap.next() {
        // Parse the Ethernet frame from the captured packet data
        if let Some(ethernet_packet) = EthernetPacket::new(&packet.data) {
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    // Handle IPv4 packets
                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                        match ipv4_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                // Handle TCP packets
                                let tcp_packet = TcpPacket::new(ipv4_packet.payload());
                                if let Some(tcp_packet) = tcp_packet {
                                    println!(
                                        "TCP Packet: {}.{}.{}.{}:{} > {}.{}.{}.{}:{}; Seq: {}",
                                        ipv4_packet.get_source().octets()[0],
                                        ipv4_packet.get_source().octets()[1],
                                        ipv4_packet.get_source().octets()[2],
                                        ipv4_packet.get_source().octets()[3],
                                        tcp_packet.get_source(),
                                        ipv4_packet.get_destination().octets()[0],
                                        ipv4_packet.get_destination().octets()[1],
                                        ipv4_packet.get_destination().octets()[2],
                                        ipv4_packet.get_destination().octets()[3],
                                        tcp_packet.get_destination(),
                                        tcp_packet.get_sequence(),
                                        // tcp_packet.get_acknowledgment(),
                                    );
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                // Handle UDP packets
                                let udp_packet = UdpPacket::new(ipv4_packet.payload());
                                if let Some(udp_packet) = udp_packet {
                                    println!(
                                        "UDP Packet: {}.{}.{}.{}:{} > {}.{}.{}.{}:{}; Len: {}",
                                        ipv4_packet.get_source().octets()[0],
                                        ipv4_packet.get_source().octets()[1],
                                        ipv4_packet.get_source().octets()[2],
                                        ipv4_packet.get_source().octets()[3],
                                        udp_packet.get_source(),
                                        ipv4_packet.get_destination().octets()[0],
                                        ipv4_packet.get_destination().octets()[1],
                                        ipv4_packet.get_destination().octets()[2],
                                        ipv4_packet.get_destination().octets()[3],
                                        udp_packet.get_destination(),
                                        udp_packet.get_length()
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
fn send_alert(ip: &str, port: u16) {
    println!("ALERT! Traffic from IP {} on port {}", ip, port);

    Notification::new()
        .summary("Network Monitoring Alert")
        .body(&format!("Traffic from IP {} on port {}", ip, port))
        .show().unwrap();
} 