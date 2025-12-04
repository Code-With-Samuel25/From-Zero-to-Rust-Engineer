// SRC INDUSTRIES // RED TEAM TOOL #001 – Silent LAN Scanner
//Made by S-Curry

use pnet::datalink::{
    self, Channel, Config, DataLinkSender, NetworkInterface, MacAddr,
};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::Packet;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

fn main() {
    println!("SRC INDUSTRIES // RED TEAM TOOL #001");
    println!("Silent LAN discovery – Stage 2 active\n");

    let interface = find_best_interface();
    let own_ip = get_own_ip(&interface);

    println!("Using interface : {}", interface.name);
    println!("Your IP         : {}", own_ip);
    println!("Your MAC        : {}", format_mac(interface.mac));

    let config = Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(Duration::from_secs(1)),
        write_timeout: Some(Duration::from_secs(1)),
        channel_type: pnet::datalink::ChannelType::Layer2,
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Wrong channel type"),
        Err(e) => panic!("Failed to create channel: {}", e),
    };

    send_arp_broadcast(&interface, &mut tx, own_ip);

    let mut discovered: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
    let deadline = Instant::now() + Duration::from_secs(3);

    println!("\nListening for replies (3s stealth window)...\n");

    while Instant::now() < deadline {
        match rx.next() {
            Ok(packet) => {
                if let Some((ip, mac)) = parse_arp_reply(packet, own_ip) {
                    if discovered.insert(ip, mac).is_none() {
                        println!("  • {}  →  {}", ip, format_mac(Some(mac)));
                    }
                }
            }
            Err(_) => continue,
        }
    }

    println!("\nDiscovered {} live devices.", discovered.len());
}

fn find_best_interface() -> NetworkInterface {
    let all = datalink::interfaces();

    if let Some(iface) = all.iter().find(|i| {
        i.is_up()
            && !i.is_loopback()
            && i.mac.is_some()
            && i.ips.iter().any(|ip| matches!(ip, pnet::ipnetwork::IpNetwork::V4(v4) if v4.ip().is_private()))
    }) {
        return iface.clone();
    }

    if let Some(iface) = all.iter().find(|i| {
        i.is_up()
            && !i.is_loopback()
            && i.mac.is_some()
            && i.ips.iter().any(|ip| matches!(ip, pnet::ipnetwork::IpNetwork::V4(_)))
    }) {
        println!("Warning: No private IP – using interface with public/link-local IP: {}", iface.name);
        return iface.clone();
    }

    if let Some(iface) = all.iter().find(|i| i.is_up() && !i.is_loopback() && i.mac.is_some()) {
        println!("Warning: No IP assigned – using raw L2 interface: {}", iface.name);
        return iface.clone();
    }

    all.into_iter()
        .find(|i| !i.is_loopback())
        .unwrap_or_else(|| panic!("No usable network interface found. Connect to a network or run as Administrator."))
}

fn get_own_ip(interface: &NetworkInterface) -> Ipv4Addr {
    for net in &interface.ips {
        if let pnet::ipnetwork::IpNetwork::V4(net) = net {
            let ip = net.ip();
            if ip.is_private() || ip.is_loopback() {
                return ip;
            }
        }
    }
    Ipv4Addr::new(192, 168, 1, 133)
}

fn format_mac(mac: Option<MacAddr>) -> String {
    mac.map(|m| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m.0, m.1, m.2, m.3, m.4, m.5))
        .unwrap_or("??:??:??:??:??:??".to_string())
}

fn send_arp_broadcast(
    interface: &NetworkInterface,
    tx: &mut Box<dyn DataLinkSender>,
    own_ip: Ipv4Addr,
) {
    let mut eth_buffer = [0u8; 42];
    let mut ethernet = MutableEthernetPacket::new(&mut eth_buffer).unwrap();

    ethernet.set_destination(MacAddr::broadcast());
    ethernet.set_source(interface.mac.unwrap_or(MacAddr::zero()));
    ethernet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(interface.mac.unwrap_or(MacAddr::zero()));
    arp.set_sender_proto_addr(own_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(Ipv4Addr::BROADCAST);

    ethernet.set_payload(arp.packet());
    let _ = tx.send_to(ethernet.packet(), None);
}

fn parse_arp_reply(packet: &[u8], own_ip: Ipv4Addr) -> Option<(Ipv4Addr, MacAddr)> {
    let ethernet = EthernetPacket::new(packet)?;
    if ethernet.get_ethertype() != EtherTypes::Arp { return None; }

    let arp = ArpPacket::new(ethernet.payload())?;
    if arp.get_operation() != ArpOperations::Reply { return None; }
    if arp.get_sender_proto_addr() == own_ip { return None; }

    Some((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()))
}