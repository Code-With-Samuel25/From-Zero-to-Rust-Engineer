// SRC INDUSTRIES // RED TEAM TOOL #002
// Silent LAN scanner + passive & active OS/device fingerprinting
// Made by S-Curry

use pnet::datalink::{NetworkInterface, MacAddr};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use serde::Serialize;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[derive(Serialize, Debug, Clone)]
struct Device {
    ip: Ipv4Addr,
    mac: String,
    vendor: String,
    os_guess: String,
    open_ports: Vec<u16>,
}

fn main() {
    println!("SRC INDUSTRIES // RED TEAM TOOL #002");
    println!("Silent discovery + OS & device fingerprinting\n");

    let interface = find_interface();
    let own_ip = get_own_ip(&interface);

    println!("Interface : {}", interface.name);
    println!("Your IP   : {}", own_ip);
    println!("Your MAC  : {}\n", format_mac(interface.mac));

    let (mut tx, mut rx) = create_channel(&interface);

    // phase 1: silent ARP broadcast
    send_arp_broadcast(&interface, &mut tx, own_ip);

    // phase 2: listen + fingerprint for 4 seconds
    let mut devices: HashMap<Ipv4Addr, Device> = HashMap::new();
    let deadline = Instant::now() + Duration::from_secs(4);

    println!("Sniffing & Fingerprinting (4s stealth window)...\n");

    while Instant::now() < deadline {
        if let Ok(packet) = rx.next() {
            if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                // ARP replies
                if ethernet.get_ethertype() == EtherTypes::Arp {
                    if let Some((ip, mac)) = parse_arp_reply(&ethernet) {
                        add_or_update_device(&mut devices, ip, mac);
                    }
                }

                // Passive TCP fingerprinting
                if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ip_packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet.payload()) {
                        if let Some(tcp) = TcpPacket::new(ip_packet.payload()) {
                            let src_ip = ip_packet.get_source();
                            if let Some(dev) = devices.get_mut(&src_ip) {
                                let dest_port = tcp.get_destination();
                                if !dev.open_ports.contains(&dest_port) {
                                    dev.open_ports.push(dest_port);
                                }
                                update_os_guess(dev, &tcp, ip_packet.get_ttl());
                            }
                        }
                    }
                }
            }
        }
    }

    // print results
    println!("{:<15} {:<17} {:<25} {:<20} Ports", "IP", "MAC", "Vendor", "OS Guess");
    println!("{}", "-".repeat(90));
    for dev in devices.values() {
        println!(
            "{:<15} {:<17} {:<25} {:<20} {:?}",
            dev.ip, dev.mac, dev.vendor, dev.os_guess, dev.open_ports
        );
    }
    println!("\nSRC owns {} devices", devices.len());
}

fn find_interface() -> NetworkInterface {
    pnet::datalink::interfaces()
        .into_iter()
        .find(|i| i.is_up() && !i.is_loopback() && i.ips.iter().any(|n| n.is_ipv4()))
        .expect("No valid interface – connect to Wi-Fi")
}

fn get_own_ip(interface: &NetworkInterface) -> Ipv4Addr {
    interface
        .ips
        .iter()
        .find_map(|net| match net {
            pnet::ipnetwork::IpNetwork::V4(v4) => Some(v4.ip()),
            _ => None,
        })
        .unwrap_or(Ipv4Addr::new(192, 168, 1, 100))
}

fn format_mac(mac: Option<MacAddr>) -> String {
    mac.map(|m| {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m.0, m.1, m.2, m.3, m.4, m.5
        )
    })
    .unwrap_or("??:??:??:??:??:??".to_string())
}

fn create_channel(
    interface: &NetworkInterface,
) -> (
    Box<dyn pnet::datalink::DataLinkSender>,
    Box<dyn pnet::datalink::DataLinkReceiver>,
) {
    match pnet::datalink::channel(interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Channel error"),
    }
}

fn send_arp_broadcast(
    interface: &NetworkInterface,
    tx: &mut Box<dyn pnet::datalink::DataLinkSender>,
    own_ip: Ipv4Addr,
) {
    let mut eth_buffer = [0u8; 42];
    let mut eth_packet = MutableEthernetPacket::new(&mut eth_buffer).unwrap();

    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_source(interface.mac.unwrap());
    eth_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(own_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(Ipv4Addr::BROADCAST);

    eth_packet.set_payload(arp_packet.packet());

    let _ = tx.send_to(eth_packet.packet(), None);
}

fn parse_arp_reply(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
) -> Option<(Ipv4Addr, MacAddr)> {
    use pnet::packet::arp::ArpPacket;
    if ethernet.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(ethernet.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    Some((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()))
}

fn add_or_update_device(devices: &mut HashMap<Ipv4Addr, Device>, ip: Ipv4Addr, mac: MacAddr) {
    let vendor = mac_to_vendor(mac);
    devices.entry(ip).or_insert_with(|| Device {
        ip,
        mac: format_mac(Some(mac)),
        vendor: vendor.clone(),
        os_guess: "Unknown".to_string(),
        open_ports: vec![],
    });
}

fn update_os_guess(dev: &mut Device, tcp: &TcpPacket, ttl: u8) {
    let _window = tcp.get_window();
    dev.os_guess = if ttl <= 64 {
        "Linux/Unix".to_string()
    } else if ttl <= 128 {
        "Windows".to_string()
    } else {
        "Other".to_string()
    };
}

fn mac_to_vendor(mac: MacAddr) -> String {
    let oui = ((mac.0 as u32) << 16) | ((mac.1 as u32) << 8) | (mac.2 as u32);
    match oui {
        0x00C0EE => "Apple".to_string(),
        0x0050C2 => "Samsung".to_string(),
        0xEC172F => "TP-Link".to_string(),
        0x001BC5 => "Huawei".to_string(),
        _ => format!("{:02x}:{:02x}:{:02x}", mac.0, mac.1, mac.2),
    }
}