extern crate pcap;
extern crate pnet;
extern crate notify_rust;



use druid::widget::{Label,Button,Flex};
use druid::{AppLauncher, LocalizedString, Widget, WidgetExt, WindowDesc};
use notify_rust::Notification;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::sync::{Arc,Mutex};
use std::thread;

struct AppState{
    monitoring: bool,
}

impl AppState{
    fn new() -> Self{
        AppState{monitoring: false}
    }
    //This is the default conctructor for the AppState structure
}

fn find_icon_path() -> Option<String> {
    let icon_path = "";
    if std::path::Path::new(&icon_path).exists() {
        Some(icon_path.to_string())
    } else {
        None
    }
}


fn start_network_monitoring() {
    let interface = "ens33";

    let mut cap = pcap::Capture::from_device(interface)
        .unwrap()
        .promisc(true)
        .snaplen(5000)
        .open()
        .unwrap();

    while let Ok(packet) = cap.next() {
        if let Some(ethernet_packet) = EthernetPacket::new(&packet.data) {
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                        match ipv4_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
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
                                    );
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
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
                                        udp_packet.get_length(),
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
        .show()
        .unwrap();
}

fn ui_builder() -> impl Widget<String> { //This will always return a widget

    let header = Flex::row()
    .with_child(Button::new("Start").on_click(|_ctx, _data: &mut String, _env|{
        println!("Start clicked"); //printing in the terminal
    }))
    .with_child(Button::new("Stop").on_click(|_ctx, _data: &mut String, _env|{
        println!("Stopped execution");
    }));

    // // Create a label widget to display the main content
    // let label = Label::new(|_data: &String, _env: &_| "Network Cloner".to_string())
    //     .with_text_size(24.0)
    //     .center();

    //we will combine the label and the header using a flex widget and then that widget will be returned 
    // Flex::column()
    // .with_child(header)
    // .with_child(label)
    // .padding(10.0) //this will be returned

    //Labels for TCP 
    let heading_tcp = Label::new("TCP")
    .with_text_size(25.0);
    // .align_horizontal(druid::widget::Alignment::center());

    let tcp_labels = Flex::column()
    .with_child(Label::new("Record 1"))
    .with_child(Label::new("Record 2"));


    //UDP labels
    let heading_udp = Label::new("UDP")
    .with_text_size(25.0);
    // .align_horizontal(druid::widget::Alignment::center());

    let udp_labels = Flex::column()
    .with_child(Label::new("Record 1"))
    .with_child(Label::new("Record 2"));


    Flex::column()
    .with_child(header)
    .with_spacer(20.0)
    .with_flex_child(Flex::row()
        .with_child(Flex::column()
        .with_child(heading_tcp)
        .with_flex_child(tcp_labels, 1.0))
        .with_spacer(350.0)
        .with_child(Flex::column()
        .with_child(heading_udp)
        .with_flex_child(udp_labels,1.0)),
    1.0)
    .padding(20.0)
    //Returning the flx widget made up of combination of flex widgets
}
fn main() {
    
    // start_network_monitoring();
    let window = WindowDesc::new(ui_builder())
    .title(LocalizedString::new("Hello World!"))
    .window_size((600.0, 400.0));

    // Create the application launcher
    let app = AppLauncher::with_window(window);

    // Launch the application
    app.launch(String::from("Hello, Druid!")).expect("Failed to launch application");
}
