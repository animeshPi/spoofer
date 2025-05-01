use dialoguer::{
    theme::ColorfulTheme, 
    MultiSelect, 
    Select,
    Input,
    console::Style
};
use std::io;
use std::process::Command;
use std::str;
use regex::Regex;
use get_if_addrs::get_if_addrs;

pub fn select_device(devices: &[String]) -> io::Result<usize> {
    let theme = ColorfulTheme {
        active_item_prefix: Style::new().apply_to("⮚".to_string()),
        inactive_item_prefix: Style::new().apply_to("  ".to_string()),
        active_item_style: Style::new().green().bright(),
        inactive_item_style: Style::new().white(),
        ..ColorfulTheme::default()
    };

    println!("Select network devices from the list:");

    let selection = Select::with_theme(&theme)
        .with_prompt("Choose network devices")
        .items(devices)
        .default(0)
        .interact()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(selection)
}

pub fn get_local_ip() -> io::Result<String> {
    let interfaces = get_if_addrs().map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Error getting interfaces: {}", e))
    })?;

    for interface in interfaces {
        let ip = interface.ip();
        if ip.is_ipv4() && !ip.is_loopback() {
            return Ok(ip.to_string());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "No valid local IPv4 address found"
    ))
}

pub fn scan_ips(selected_device: &str, local_ip: &str) -> io::Result<Vec<String>> {
    let output = Command::new("sudo")
        .arg("arp-scan")
        .arg("-I")
        .arg(selected_device)
        .arg("-l")
        .output()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to execute arp-scan: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("arp-scan failed: {}", stderr)
        ));
    }

    let output_str = str::from_utf8(&output.stdout)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let ip_regex = Regex::new(r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2[0-9]|3[0-1])(?:\.\d{1,3}){2})\b")
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let mut ips = Vec::new();
    for ip_match in ip_regex.find_iter(output_str) {
        let ip = ip_match.as_str().to_string();
        if ip != local_ip {
            ips.push(ip);
        }
    }

    Ok(ips)
}

pub fn select_ips(ip_addresses: &[String], gateway_ip: &str) -> io::Result<Vec<usize>> {
    let theme = ColorfulTheme {
        unchecked_item_prefix: Style::new().apply_to("❏ ".to_string()),
        checked_item_prefix: Style::new().apply_to("🗹".to_string()),
        active_item_style: Style::new().green().bright(),
        inactive_item_style: Style::new().white(),
        ..ColorfulTheme::default()
    };

    // Filter out the gateway IP and store mapping
    let filtered: Vec<(usize, &String)> = ip_addresses
        .iter()
        .enumerate()
        .filter(|(_, ip)| ip != &gateway_ip)
        .collect();

    let display_ips: Vec<&String> = filtered.iter().map(|(_, ip)| *ip).collect();

    // Print gateway info
    println!("Gateway IP: {}\n", gateway_ip);

    if display_ips.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "No IP addresses available to select",
        ));
    } else {
        println!("Select IP addresses from the list:");
        println!("Use SPACE to select, ENTER to confirm, 'a' to toggle all");
    }

    let selected = MultiSelect::with_theme(&theme)
        .with_prompt("Choose IP addresses")
        .items(&display_ips)
        .interact()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Map selected indices back to original indices
    let result: Vec<usize> = selected.iter().map(|&i| filtered[i].0).collect();

    Ok(result)
}

pub fn prompt_retry(prompt: &str) -> io::Result<bool> {
    let theme = ColorfulTheme::default();
    let input: String = Input::with_theme(&theme)
        .with_prompt(format!("{} ", prompt))
        .allow_empty(true)
        .interact_text()?;

    Ok(input.to_lowercase().trim().is_empty() || 
        matches!(input.to_lowercase().as_str(), "y" | "yes"))
}
