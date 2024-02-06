extern crate pcap;
extern crate pnet;
extern crate notify_rust;



use bytes::Bytes;
use druid::widget::{Label,Button,Flex,Scroll};
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
                                    let payload_bytes = Bytes::copy_from_slice(tcp_packet.payload());
                                    println!(
                                        "TCP Packet: {}.{}.{}.{}:{} > {}.{}.{}.{}:{}; Seq: {} \n Content: {:?}",
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
                                        payload_bytes,
                                    );
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                let udp_packet = UdpPacket::new(ipv4_packet.payload());
                                if let Some(udp_packet) = udp_packet {
                                    let payload_bytes = Bytes::copy_from_slice(udp_packet.payload());
                                    println!(
                                        "UDP Packet: {}.{}.{}.{}:{} > {}.{}.{}.{}:{}; Len: {} \n Payload: {:?}",
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
                                        payload_bytes
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

    //default state of the networking function
    let monitoring_state = Arc::new(Mutex::new(AppState::new()));

    let header = Flex::row()
        .with_child(Button::new("Start").on_click({
            let monitoring_state = Arc::clone(&monitoring_state);
            move |_ctx, _data: &mut String, _env| {
                println!("Start button clicked\n Started execution..");
                let mut state = monitoring_state.lock().unwrap();
                if !state.monitoring{
                    state.monitoring = true;
                    let monitoring_state = Arc::clone(&monitoring_state);
                    thread::spawn(move || start_network_monitoring());
                }
        }
    }))
    .with_child(Button::new("Stop").on_click({
        let monitoring_state = Arc::clone(&monitoring_state);
        move |_ctx, _data: &mut String, _env| {
            println!("Stopped execution...");
            let mut state = monitoring_state.lock().unwrap();
            state.monitoring = false;
        }
    }));

    let button_container = Flex::column().with_child(Button::new("Initial Button"))
        .on_click(|_,_,_|{
            println!("Clicked");
        });
    
    let scrollable_container = Scroll::new(button_container)
        .vertical();
        // .controller(druid::widget::ScrollController::default());
    
    Flex::column()
        .with_child(header)
        .with_child(scrollable_container)
        .padding(20.0)

    //Labels for TCP 
    // let heading_tcp = Label::new("TCP")
    // .with_text_size(25.0);
    // // .align_horizontal(druid::widget::Alignment::center());

    // let tcp_labels = Flex::column()
    // .with_child(Label::new("Record 1"))
    // .with_child(Label::new("Record 2"));


    // //UDP labels
    // let heading_udp = Label::new("UDP")
    // .with_text_size(25.0);
    // // .align_horizontal(druid::widget::Alignment::center());

    // let udp_labels = Flex::column()
    // .with_child(Label::new("Record 1"))
    // .with_child(Label::new("Record 2"));


    // Flex::column()
    // .with_child(header)
    // .with_spacer(20.0)
    // .with_flex_child(Flex::row()
    //     .with_child(Flex::column()
    //     .with_child(heading_tcp)
    //     .with_flex_child(tcp_labels, 1.0))
    //     .with_spacer(350.0)
    //     .with_child(Flex::column()
    //     .with_child(heading_udp)
    //     .with_flex_child(udp_labels,1.0)),
    // 1.0)
    // .padding(20.0)
    //Returning the flx widget made up of combination of flex widgets
}

fn start_networking_thread(monitoring_state: Arc<Mutex<AppState>>){
    let state = monitoring_state.lock().unwrap();
    loop{
    if !state.monitoring{
        break;
    }
}
    start_network_monitoring();
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
