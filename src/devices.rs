use get_if_addrs::get_if_addrs;
use std::net::Ipv4Addr;
use std::{
    collections::HashMap,
    fs,
    io,
    path::Path,
};

#[derive(Debug)]
pub struct NetworkDevice {
    pub name: String,
    pub mac: String,
    pub ips: Vec<String>,
    pub is_up: bool,
}

pub fn get_network_devices() -> io::Result<Vec<NetworkDevice>> {
    let interfaces = get_if_addrs()?;
    let mut devices_map = HashMap::new();

    // First pass: Collect all interfaces and their IPs
    for iface in interfaces {
        let entry = devices_map.entry(iface.name.clone()).or_insert(NetworkDevice {
            name: iface.name.clone(),
            mac: String::new(),
            ips: Vec::new(),
            is_up: false,
        });
        
        entry.ips.push(iface.addr.ip().to_string());
    }

    // Second pass: Get MAC and status from sysfs
    for device in devices_map.values_mut() {
        // Get MAC address from sysfs
        let mac_path = Path::new("/sys/class/net").join(&device.name).join("address");
        device.mac = fs::read_to_string(mac_path)
            .map(|m| m.trim().to_string())
            .unwrap_or_else(|_| "N/A".to_string());

        // Get interface status from sysfs flags
        let flags_path = Path::new("/sys/class/net").join(&device.name).join("flags");
        let flags = fs::read_to_string(flags_path)
            .ok()
            .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);

        // IFF_UP flag = 0x1 (from Linux if.h)
        device.is_up = (flags & 0x1) != 0;
    }

    Ok(devices_map.into_values().collect())
}

// Tells the IP of the Gateway/Router
pub fn get_linux_gateway_ip() -> String {
    let content = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    
    for line in content.lines().skip(1) {  // Skip header
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == "00000000" {
            let gateway_hex = fields[2];
            if gateway_hex.len() != 8 {
                continue;
            }
            
            if let Ok(gateway_int) = u32::from_str_radix(gateway_hex, 16) {
                let octets = [
                    (gateway_int & 0xFF) as u8,
                    ((gateway_int >> 8) & 0xFF) as u8,
                    ((gateway_int >> 16) & 0xFF) as u8,
                    ((gateway_int >> 24) & 0xFF) as u8,
                ];
                return Ipv4Addr::from(octets).to_string();
            }
        }
    }
    String::new()  // Return empty string if not found
}
