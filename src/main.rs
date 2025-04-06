mod cli;
mod devices;

use devices::{get_linux_gateway_ip, get_network_devices};
use cli::{get_local_ip, scan_ips, select_ips};
use std::io;

fn main() -> io::Result<()> {
    // Get network devices
    let devices = get_network_devices()?;
    
    let device_names: Vec<String> = devices.iter()
        .map(|d| d.name.clone()) // Adjust based on your NetworkDevice struct
        .collect();

    let selected_index = cli::select_device(&device_names)?;
    let selected_device = &devices[selected_index].name.clone();

    // Get local IP address
    let local_ip = match get_local_ip() {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("Error: {}", e);
            return Ok(());
        }
    };

    // Scan for other IP addresses
    let ips = match scan_ips(&selected_device, &local_ip) {
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

    // Handle selected IPs
    if selected_indices.is_empty() {
        println!("No IP addresses selected!");
    } else {
        println!("\nSelected IP addresses:");
        for index in selected_indices {
            println!("- {}", ips[index]);
        }
    }

    // Add your additional processing logic here

    Ok(())
}
