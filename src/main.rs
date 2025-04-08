mod cli;
mod devices;
mod arp_spoof;

use arp_spoof::start_arp_spoofing;
use devices::{get_linux_gateway_ip, get_network_devices};
use cli::{get_local_ip, scan_ips, select_ips};
use std::{io, net::Ipv4Addr};

fn main() -> io::Result<()> {
    // Get network devices
    let devices = get_network_devices()?;
    
    let device_names: Vec<String> = devices.iter()
        .map(|d| d.name.clone()) // Adjust based on your NetworkDevice struct
        .collect();

    let selected_index = cli::select_device(&device_names)?;
    let selected_interface = &devices[selected_index].name.clone();

    // Get local IP address
    let local_ip = match get_local_ip() {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("Error: {}", e);
            return Ok(());
        }
    };

    // Scan for other IP addresses
    let ips = match scan_ips(selected_interface, &local_ip) {
        Ok(ips) => ips,
        Err(e) => {
            eprintln!("Scanning error: {}", e);
            return Ok(());
        }
    };

    if ips.is_empty() {
        println!("No IP addresses found!");
        return Ok(());
    }

    let gateway_ip = get_linux_gateway_ip(); // Assuming the first IP is the gateway
    // Select IPs through CLI interface
    let selected_indices = select_ips(&ips, &gateway_ip)?;
    let selected_targets = selected_indices.clone();

    // Handle selected IPs
    if selected_indices.is_empty() {
        println!("No IP addresses selected!");
    } else {
        println!("\nSelected IP addresses:");
        for index in selected_indices {
            println!("- {}", ips[index]);
        }
    }

    // For parameters in spoof running function
    let gateway_ip = gateway_ip.parse::<Ipv4Addr>().unwrap();

    let target_ips: Vec<Ipv4Addr> = selected_targets.iter()
        .map(|&i| ips[i].parse::<Ipv4Addr>().unwrap())
        .collect();
    // Start ARP spoofing
    match start_arp_spoofing(selected_interface, target_ips, gateway_ip) {
        Ok(_) => println!("ARP spoofing started successfully."),
        Err(e) => eprintln!("Error starting ARP spoofing: {}", e),
    }

    Ok(())
}
