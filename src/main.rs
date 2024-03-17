extern crate pcap;
extern crate pnet;
extern crate notify_rust;

use bytes::Bytes;
use notify_rust::Notification;
use druid::widget::{Button, Flex, Label,Align,TextBox,Container,Scroll};
use druid::{AppLauncher, Data, Env, Lens, LocalizedString, Widget, WidgetExt, WindowDesc};
use std::{process, result, string, thread};
use std::sync::{Arc,Mutex};
use std::time::Duration;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use crate::my_app_state_derived_lenses::vec1;
#[derive(Clone, Data, Lens)]


//add fn that makes the line or label that has the detail of each packet
//add fn to make the rule line colored
//try to highlight the panels with different dim colors
//add fn that start and stops the execution
//add the fn that stores the data received from the packet then stores it into some storage data structure and then it is accessed by the fn that changes the data of the panel
//show the vector contents once the content has been checked by the flag_malicious function

struct MyAppState {
    #[data(same_fn = "PartialEq::eq")]
    vec1: Vec<String>,
    #[data(same_fn = "PartialEq::eq")]
    vec2: Vec<String>,
    input_text: String,
    input_text1: String,
    input_text2: String,
}

impl Default for MyAppState {
    fn default() -> Self {
        Self {
            vec1: Vec::new(),
            vec2: Vec::new(),
            input_text: String::new(),
            input_text1: String::new(),
            input_text2: String::new(),
        }
    }
}


fn flag_malicious(payload: &[u8]){
    let payloads: Vec<&[u8]> = vec![
    b"'; DROP TABLE users; --",
    b"1' OR '1'='1",
    b"<script>alert('XSS Attack!');</script>",
    b"<img src=\"javascript:alert('XSS Attack!');\">",
    b"; rm -rf /",
    b"../../../../../../../etc/passwd",
    b"../..//..//..//etc/passwd",
    b"<?php system($_GET['cmd']); ?>",
    b"| rm -rf /",
];
for p in payloads {
    if std::str::from_utf8(p).unwrap().contains(std::str::from_utf8(payload).unwrap()) {
        println!("Payload is malicious: {:?}", p);
        return;
    }
}
println!("Payload is not malicious");
}
fn main() {
    
    let main_window = WindowDesc::new(build_ui())
        .title(LocalizedString::new("Sniffer"));

    // let initial_state = (MyAppState::default());
    let shared_state = Arc::new(Mutex::new(MyAppState::default()));

    // Clone the shared state for the input loop
    let input_shared_state = shared_state.clone();
     // Spawn a thread for the input loop
    thread::spawn(move || {
        loop {
            let mut input = String::new();
            println!("Enter text:");
            std::io::stdin().read_line(&mut input).expect("Failed to read input");

            // Update the shared state with the input text
            let mut state = input_shared_state.lock().unwrap();
            state.input_text = input.trim().to_string();
        }
    });

    let shared_state_ref = shared_state.lock().unwrap();
    // Launch the Druid application with the main window and shared state
    AppLauncher::with_window(main_window)
        .use_simple_logger()
        .launch(shared_state_ref.clone())
        .expect("Failed to launch application");

   
}
fn create_file_button()-> impl Widget<MyAppState>{
    Button::new("File")
    .on_click(|_ctx,data: &mut MyAppState, _env|
    {
        println!("{:?}","File button clicked");
    })
    .padding((5.0,0.0))
}
fn create_exit_button()-> impl Widget<MyAppState>{
    Button::new("Exit")
    .on_click(|_ctx,data: &mut MyAppState, _env|
    {
        process::exit(0);
    })
    .padding((5.0,0.0))
}
fn create_start_button()-> impl Widget<MyAppState>{
    Button::new("Start")
    .on_click(|_ctx,data: &mut MyAppState, _env|
    {
        // start_networking()
    })
    .padding((5.0,0.0))
}
fn port_change(s:&mut String){
    // call the start_execution with this portnumber and execute the stop_execution function
}
fn create_stop_button()-> impl Widget<MyAppState>{
    Button::new("Stop")
    .on_click(|_ctx,data: &mut MyAppState, _env|
    {
        // stop_exeuction
    })
    .padding((5.0,0.0))
}
fn start_network_monitoring() -> (String,String) {
    let interface = "ens33";
    let mut result_tcp = String::new();
    let mut result_udp = String::new();

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
                                    result_tcp.push_str(&format!(
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
                                    ));
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                let udp_packet = UdpPacket::new(ipv4_packet.payload());
                                if let Some(udp_packet) = udp_packet {
                                    let payload_bytes = Bytes::copy_from_slice(udp_packet.payload());
                                    result_udp.push_str(&format!(
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
                                    ));
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
    (result_tcp,result_udp)
}
fn build_ui() -> impl Widget<MyAppState> {
    let input_text_box = TextBox::new()
    .with_placeholder("Enter something")
    .lens(MyAppState::input_text);
    let input_text_box1= TextBox::new()
        .with_placeholder("Enter something")
        .lens(MyAppState::input_text1);
    let input_text_box2= TextBox::new()
        .with_placeholder("Enter something")
        .lens(MyAppState::input_text2);

    let panel_hidden = Flex::column()
    .with_child(Label::new(""))
    .with_child(input_text_box)
    .with_child(Button::new("Submit").on_click(|_ctx, data: &mut MyAppState, _env| {
        // Use the stored data from the text box
        let mut input_data = data.input_text.clone();
        println!("Stored input data: {}", input_data);
        // port_change(&mut input_data);
        // You can use input_data variable here or pass it to another function
    }));
    let panel_hidden1 = Flex::column()
    .with_child(Label::new(""))
    .with_child(input_text_box1)
    .with_child(Button::new("Submit").on_click(|_ctx, data: &mut MyAppState, _env| {
        // Use the stored data from the text box
        // data.vec1.clear(); // Clear existing values
        data.vec1.push(start_network_monitoring().0);
        let app_state_now = MyAppState{
            vec1: vec![data.input_text1.clone()],
            vec2:vec![],
            input_text:  "input".to_string(),
            input_text1: "input".to_string(),
            input_text2: "input".to_string(),
        };
        println!("{:?}", app_state_now.vec1);
        // You can use input_data variable here or pass it to another function
    }));
    
    let panel_hidden2 = Flex::column()
        .with_child(Label::new(""))
        .with_child(input_text_box2)
        .with_child(Button::new("Submit").on_click(|_ctx, data: &mut MyAppState, _env| {
        // Use the stored data from the text box
        // data.vec1.clear(); // Clear existing values
        data.vec2.push(start_network_monitoring().1);
        let app_state_now = MyAppState{
            vec1: vec![data.input_text2.clone()],
            vec2:vec![],
            input_text:  "input".to_string(),
            input_text1: "input".to_string(),
            input_text2: "input".to_string(),
        };
        println!("{:?}", app_state_now.vec2);
        // You can use input_data variable here or pass it to another function
    }));

    let toolbar = Align::left(Flex::row()
    .with_child(create_file_button())
    .with_spacer(10.0) // Add spacer between buttons
    .with_child(create_start_button())
    .with_spacer(10.0) // Add spacer between buttons
    .with_child(create_stop_button())
    .with_spacer(10.0) // Add spacer between buttons
    .with_child(create_exit_button())
    .with_spacer(400.0)
    .with_child((Label::new("Port")).padding((5.0,0.0)))
    .with_child(panel_hidden)
    .with_child((Label::new("Panel1")).padding((5.0,0.0)))
    .with_child(panel_hidden1)
    .with_child((Label::new("Panel2")).padding((5.0,0.0)))
    .with_child(panel_hidden2));

    
    let vec1_label = Label::dynamic(|data: &MyAppState, _env| {
        data.vec1.iter().map(|item| format!("{:?}", item)).collect::<Vec<_>>().join("\t")
    })
    .padding(10.0);
    
    let vec2_label = Label::dynamic(|data: &MyAppState, _env| {
        data.vec2.iter().map(|item| format!("{:?}", item)).collect::<Vec<_>>().join("\t")
    })
    .padding(10.0);
    
    let tcp_label = Label::new("TCP Packets: ")
        .padding((5.0,0.0));
    let udp_label = Label::new("UDP Packets")
        .padding((5.0,0.0));

    let panel_vec1 = Align::left(Flex::column()
        .with_child(tcp_label)
        .with_child(vec1_label)
        .padding(10.0));

    let panel_vec2 =  Align::left(Flex::column()
        .with_child(udp_label)
        .with_child(vec2_label)
        .padding(10.0));

    
    let main_panel = Flex::column()
        .with_child(panel_vec1)
        .with_flex_spacer(20.0)
        .with_child(panel_vec2)
        .padding(10.0);

    Flex::column()
        .with_child(toolbar)
        .with_spacer(10.0) // Add some space between toolbar and main panel
        .with_flex_child(main_panel,1.0)
        .padding(10.0)

}


// // fn build_ui() -> impl Widget<AppState> {
// //     // Create some mock content for the scrollable panel
// //     let mut content = Flex::column();
// //     for i in 0..200 {
// //         content.add_child(Label::new(format!("Item {}", i)));
// //     }

// //     // Wrap the content in a Scroll widget to make it scrollable
// //     Scroll::new(content)
// // }




