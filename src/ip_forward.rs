use std::fs;
use std::io;

/// RAII guard for Linux IPv4 forwarding
pub struct IpForwardGuard {
    original: String,
}

impl IpForwardGuard {
    /// Enables IP forwarding and remembers the original value
    pub fn new() -> io::Result<Self> {
        let path = "/proc/sys/net/ipv4/ip_forward";

        // Read original state
        let original = fs::read_to_string(path)?.trim().to_string();

        // Enable forwarding
        fs::write(path, "1")?;

        println!("IP forwarding enabled");

        Ok(Self { original })
    }
}

impl Drop for IpForwardGuard {
    fn drop(&mut self) {
        let path = "/proc/sys/net/ipv4/ip_forward";

        if let Err(e) = fs::write(path, &self.original) {
            eprintln!("Failed to restore IP forwarding state: {}", e);
        } else {
            println!("IP forwarding restored to {}", self.original);
        }
    }
}
