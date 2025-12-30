use std::fs;
use std::io;
use std::sync::OnceLock;

static ORIGINAL_STATE: OnceLock<String> = OnceLock::new();

fn read_ip_forward() -> io::Result<String> {
    Ok(fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?
        .trim()
        .to_string())
}

pub fn enable_ip_forwarding() -> io::Result<()> {
    let current = read_ip_forward()?;
    ORIGINAL_STATE.set(current).ok();

    fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    Ok(())
}

pub fn restore_ip_forwarding() -> io::Result<()> {
    if let Some(original) = ORIGINAL_STATE.get() {
        fs::write("/proc/sys/net/ipv4/ip_forward", original)?;
    }
    Ok(())
}
