extern crate pcap;
extern crate pnet;
extern crate notify_rust;
extern crate gtk;


use gtk::prelude::*;
use gtk::{Box, Label, Window, WindowType, Button};
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

fn create_gui(state: Arc<Mutex<AppState>>) {
    gtk::init().expect("Failed to initialize GTK.");

    let window = Window::new(WindowType::Toplevel);
    window.set_title("Cloner");
    window.set_default_size(800, 900);

    let vbox = Box::new(gtk::Orientation::Vertical, 0);
    let hbox = Box::new(gtk::Orientation::Horizontal, 0);

    let header_label = Label::new(Some("Header Label"));
    vbox.pack_start(&header_label, false, false, 0);

    let start_button = Button::with_label("Start");
    let stop_button = Button::with_label("Stop");

    hbox.pack_start(&start_button, false, false, 0);
    hbox.pack_start(&stop_button, false, false, 0);

    vbox.pack_start(&hbox, false, false, 0);

    if let Some(icon_path) = find_icon_path() {
        window.set_icon_from_file(&icon_path).ok();
    }

    window.add(&vbox);
    window.show_all();

    //This will be triggered when the user closes the window to terminate the program
    window.connect_destroy(|_| {
        gtk::main_quit();
    });

    let header_label_clone = header_label.clone();
    let button1_clone = start_button.clone();
    let button2_clone = stop_button.clone();


    let state_clone = Arc::clone(&state);
    start_button.connect_clicked(move |_|{
        let mut state = state_clone.lock().unwrap();
        if !state.monitoring{
            //This starts the network monitor
            thread::spawn(move||{
                start_network_monitoring();
            });
            state.monitoring = true;
        }
    });

    //Arc is the library that updates the reference count while maintaining the memory cloning of various components
    let state_clone = Arc::clone(&state);
    stop_button.connect_clicked(move |_| {
        let mut state = state_clone.lock().unwrap();
        //This checks if the monitor is running and the button is pressed then it stops it
        if state.monitoring{
            state.monitoring = false;
        }
    });

    gtk::main();
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

fn main() {
    // create_gui();  // This will run the GUI
    // start_network_monitoring();  // This will start the network monitoring loop

    let state = Arc::new(Mutex::new(AppState::new()));
    create_gui(state);
}
