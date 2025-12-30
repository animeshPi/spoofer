use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

static FORWARDING_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn enable_ip_forwarding() -> io::Result<()> {
    fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    FORWARDING_ENABLED.store(true, Ordering::SeqCst);
    Ok(())
}

pub fn disable_ip_forwarding() -> io::Result<()> {
    fs::write("/proc/sys/net/ipv4/ip_forward", "0")?;
    FORWARDING_ENABLED.store(false, Ordering::SeqCst);
    Ok(())
}
