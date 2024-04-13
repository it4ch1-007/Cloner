// extern crate pcap;
// extern crate pnet;
// extern crate notify_rust;

use chrono::prelude::*;
use bytes::Bytes;
use std::fs::File;
use std::io::{prelude, Write};
use std::path::Path;
// use notify_rust::Notification;
use druid::widget::{Button, Flex, Label,Align,TextBox,Container,Scroll};
use druid::{AppLauncher, Data, Env, Lens, LocalizedString, Widget, WidgetExt, WindowDesc};
use std::{process, result, string, thread};
use std::sync::{Arc,Mutex};
use std::time::Duration;
// use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
// use pnet::packet::ip::IpNextHeaderProtocols;
// use pnet::packet::ipv4::Ipv4Packet;
// use pnet::packet::tcp::TcpPacket;
// use pnet::packet::udp::UdpPacket;
// use pnet::packet::Packet;

use crate::my_app_state_derived_lenses::vec1;
#[derive(Clone, Data, Lens)]



//ADD THE TIMING DELAY TO THE EXEUCTION OF THE NETWORKING FUNCTION
//TRY TO GET THE FUNCTION THAT CAN MONITOR NETWORK PACKETS ON WINDOWS
//DISPLAY IT ON THE LABELS AND ALSO MAKE THE FLAG RED WHENEVER THE PAYLOAD IS FLAGGED MALICIOUS
//THERE WILL BE A SEPARATE VECTOR THAT STORES THE NAMES OF ALL THE PAYLOADS AND THERE IPS AND ALL DETAILS THAT ARE FLAGGED MALICIOUS ACCORDING TO THE TOOL.


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


fn flag_malicious(payload: &[u8])-> bool{
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
        //URL ENCODING
        b"%27%3B%20DROP%20TABLE%20users%3B%20--",
        b"1%27%20OR%20%271%27%3D%271",
        b"%3Cscript%3Ealert%28%27XSS%20Attack%21%27%29%3B%3C/script%3E",
        b"%3Cimg%20src%3D%22javascript%3Aalert%28%27XSS%20Attack%21%27%29%3B%22%3E",
        b"%3B%20rm%20-rf%20/",
        b"../../../../../../../etc/passwd",
        b"../..//..//..//etc/passwd",
        b"%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E",
        b"%7C%20rm%20-rf%20/",
        //Double URL encoding
        b"%2527%253B%2520DROP%2520TABLE%2520users%253B%2520--",
        b"1%2527%2520OR%2520%25271%2527%253D%25271",
        b"%253Cscript%253Ealert%2528%2527XSS%2520Attack%2521%2527%2529%253B%253C/script%253E",
        b"%253Cimg%2520src%253D%2522javascript%253Aalert%2528%2527XSS%2520Attack%2521%2527%2529%253B%2522%253E",
        b"%253B%2520rm%2520-rf%2520/",
        b"../../../../../../../etc/passwd",
        b"../..//..//..//etc/passwd",
        b"%253C%253Fphp%2520system%2528%2524_GET%255B%2527cmd%2527%255D%2529%253B%2520%253F%253E",
        b"%257C%2520rm%2520-rf%2520/"
];
for p in payloads {
    if std::str::from_utf8(p).unwrap().contains(std::str::from_utf8(payload).unwrap()) {
        println!("Payload is malicious: {:?}", p);
        true;
    }
}

println!("Payload is not malicious");
false
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
fn store_payload_normal(path: &Path,s: &String){
    let mut file = match File::create(&path){
        Err(err) => panic!("Could'nt create the file  as {}",err), 
        Ok(file) => file,
    };
    match file.write_all(s.as_bytes()){
        Err(why) => panic!("Could'nt write the payload inside the file as {}",why),
        Ok(_) => println!("File written successfully :)"),
    }
}
fn store_payload_malicious(path: &Path,s: &String){
    let mut file = match File::create(&path){
        Err(err) => panic!("Could'nt create the file  as {}",err), 
        Ok(file) => file,
    };
    match file.write_all(s.as_bytes()){
        Err(why) => panic!("Could'nt write the payload inside the file as {}",why),
        Ok(_) => println!("File written successfully :)"),
    }
}
fn start_network_monitoring() -> (String,String) {
//     let interface = "ens33";
    let mut result_tcp = Utc::now().to_string();
    let mut result_udp = Utc::now().to_string();

//     let mut cap = pcap::Capture::from_device(interface)
//         .unwrap()
//         .promisc(true)
//         .snaplen(5000)
//         .open()
//         .unwrap();

//     while let Ok(packet) = cap.next() {
//         if let Some(ethernet_packet) = EthernetPacket::new(&packet.data) {
//             match ethernet_packet.get_ethertype() {
//                 EtherTypes::Ipv4 => {
//                     if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
//                         match ipv4_packet.get_next_level_protocol() {
//                             IpNextHeaderProtocols::Tcp => {
//                                 let tcp_packet = TcpPacket::new(ipv4_packet.payload());
//                                 if let Some(tcp_packet) = tcp_packet {
//                                     let payload_bytes = Bytes::copy_from_slice(tcp_packet.payload());
//                                     result_tcp.push_str(&format!(
//                                         "TCP Packet: {}.{}.{}.{}:{} > {}.{}.{}.{}:{}; Seq: {} \n Content: {:?}",
//                                         ipv4_packet.get_source().octets()[0],
//                                         ipv4_packet.get_source().octets()[1],
//                                         ipv4_packet.get_source().octets()[2],
//                                         ipv4_packet.get_source().octets()[3],
//                                         tcp_packet.get_source(),
//                                         ipv4_packet.get_destination().octets()[0],
//                                         ipv4_packet.get_destination().octets()[1],
//                                         ipv4_packet.get_destination().octets()[2],
//                                         ipv4_packet.get_destination().octets()[3],
//                                         tcp_packet.get_destination(),
//                                         tcp_packet.get_sequence(),
//                                         payload_bytes,
//                                     ));
//                                 }
//                             }
//                             IpNextHeaderProtocols::Udp => {
//                                 let udp_packet = UdpPacket::new(ipv4_packet.payload());
//                                 if let Some(udp_packet) = udp_packet {
//                                     let payload_bytes = Bytes::copy_from_slice(udp_packet.payload());
//                                     result_udp.push_str(&format!(
//                                         "UDP Packet: {}.{}.{}.{}:{} > {}.{}.{}.{}:{}; Len: {} \n Payload: {:?}",
//                                         ipv4_packet.get_source().octets()[0],
//                                         ipv4_packet.get_source().octets()[1],
//                                         ipv4_packet.get_source().octets()[2],
//                                         ipv4_packet.get_source().octets()[3],
//                                         udp_packet.get_source(),
//                                         ipv4_packet.get_destination().octets()[0],
//                                         ipv4_packet.get_destination().octets()[1],
//                                         ipv4_packet.get_destination().octets()[2],
//                                         ipv4_packet.get_destination().octets()[3],
//                                         udp_packet.get_destination(),
//                                         udp_packet.get_length(),
//                                         payload_bytes
//                                     ));
//                                 }
//                             }
//                             _ => {}
//                         }
//                     }
//                 }
//                 _ => {}
//             }
//         }
//     }
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

    let malicious_path = Path::new("mal.txt");
    let normal_path = Path::new("logs.txt");
    let vec1_label = Label::dynamic(move |data: &MyAppState, _env| {
        // data.vec1.iter().map(|item| format!("{:?}", item)).collect::<Vec<_>>().join("\t")
        
        let s1: String = start_network_monitoring().0;
        if flag_malicious(s1.as_bytes()){
            store_payload_malicious(&malicious_path, &s1);
        }
        else{
            store_payload_normal(&normal_path, &s1);
        }
        s1
        //THIS IS WHERE THE STRING CONTAINING THE PAYLOAD SHOULD COME
    })
    .padding(10.0);
    
    let vec2_label = Label::dynamic(move |data: &MyAppState, _env| {
        // data.vec2.iter().map(|item| format!("{:?}", item)).collect::<Vec<_>>().join("\t")
        let s2: String = start_network_monitoring().1;
        if flag_malicious(s2.as_bytes()){
            store_payload_malicious(&malicious_path, &s2);
        }
        else{
            store_payload_normal(&normal_path, &s2);
        }
        s2
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




