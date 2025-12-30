# Spoofer

Spoofer is a small Rust-based network tooling utility that performs ARP spoofing (ARP cache poisoning) against selected hosts on a local network and temporarily enables IP forwarding so traffic can be relayed through the attacker machine. It is intended for network testing, diagnostics, and research on networks you own or are authorized to test.

## Features

- Select a network interface from detected devices interactively.
- Scan the LAN for IPv4 hosts using `arp-scan`.
- Pick one or more targets interactively (gateway is excluded automatically).
- Start ARP spoofing with continuous ARP replies and basic live-status reporting.
- Automatically enable IP forwarding while running and restore the previous setting on exit.

## Important Safety & Legal Notice

This tool manipulates ARP tables and network traffic. Use it only on networks you own or where you have explicit permission to test. Unauthorized ARP spoofing is illegal and may disrupt production networks, services, or user devices. The authors are not responsible for misuse.

## Requirements

- Linux host (reads `/sys/class/net` and `/proc` interfaces).
- Root privileges for packet capture and ARP operations.
- `arp-scan` installed and available in PATH for network discovery (used via `sudo arp-scan -I <iface> -l`).
- libpcap / pcap support (the crate `pcap` is used).
- Rust toolchain to build from source.

Recommended packages on Debian/Ubuntu:

```
sudo apt update
sudo apt install build-essential libpcap-dev arp-scan
```

Recommended packages on RHEL/Fedora:

```
sudo dnf update
sudo dnf install arp-scan libpcap-devel
```

## Build

Clone and build the project with Cargo:

```
git clone <repo-url>
cd spoofer
cargo build --release
```

After building the release binary will be at `target/release/spoofer`.

## Usage

Run the program with root privileges (required for capturing and injecting packets):

```
sudo ./target/release/spoofer
```

Program flow (interactive):

1. Select a network device from the list (shows device name, MAC, IPs, and up/down status).
2. The tool determines the local IP and gateway IP.
3. The tool runs `arp-scan` on the selected interface to find hosts on the LAN.
4. Pick one or more IP addresses to target (gateway will be shown but excluded from selection).
5. The tool enables IP forwarding, starts ARP spoofing threads, and shows live target statuses.
6. Press `Ctrl+C` to stop — the program attempts to restore ARP tables and the original IP forwarding state.

See the main program flow in [src/main.rs](src/main.rs#L1-L200) and the ARP engine in [src/arp_spoof.rs](src/arp_spoof.rs#L1-L400).

## Implementation notes

- Network interface discovery and MAC/status reading: `src/devices.rs` reads `/sys/class/net` and uses `get_if_addrs` for IP collection.
- LAN host discovery uses the external `arp-scan` command (called with `sudo`) in `src/cli.rs`.
- Packet capture, ARP requests/replies and sending is handled with the `pcap` crate in `src/arp_spoof.rs`.
- IP forwarding is toggled by writing `/proc/sys/net/ipv4/ip_forward` in `src/ip_forward.rs`.

## Example run

1. Start the binary as root:

```
sudo ./target/release/spoofer
```

2. Select your active network interface when prompted.
3. Wait for `arp-scan` to finish, then select one or more target IPs from the list.
4. Observe live target status output. Press `Ctrl+C` to stop and restore state.

## Troubleshooting

- If `arp-scan` is not found or errors, install the package and re-run as root.
- If `pcap` fails to open the interface, ensure you are running as root and that libpcap is installed.
- If gateway detection returns empty, inspect `/proc/net/route` and ensure the system has a default route.

## Contributing

- Open an issue to discuss design, bugs, or feature requests.
- Fork the repo, make changes, and submit pull requests referencing the issue.
- Keep changes focused and add small, reviewable commits.

When contributing, follow standard Rust practices (format with `cargo fmt`, lint with `cargo clippy`).

## License

This project is licensed under the MIT License. See the `LICENSE` file at the project root for the full text. The `Cargo.toml` manifest includes `license = "MIT"`.

## Files of Interest

- Cargo manifest: [Cargo.toml](Cargo.toml#L1-L20)
- Main program flow: [src/main.rs](src/main.rs#L1-L200)
- CLI and interactive helpers: [src/cli.rs](src/cli.rs#L1-L200)
- ARP spoof engine: [src/arp_spoof.rs](src/arp_spoof.rs#L1-L400)
- Device detection: [src/devices.rs](src/devices.rs#L1-L200)
- IP forwarding helper: [src/ip_forward.rs](src/ip_forward.rs#L1-L200)

## Future development

Planned improvements and features to make `spoofer` more flexible and suitable for automation, testing, and packaging:

- CLI mode (non-interactive): add command-line flags for full non-interactive operation so the tool can be used in scripts and automation. Example (planned):

```bash
sudo spoofer --interface eth0 --targets 192.168.1.10,192.168.1.11 \
	--gateway 192.168.1.1 --yes --output json
```

- A script to install and put the binary in the /usr/local/bin for use.

- TUI + CLI parity: keep the existing terminal UI/TUI selection flow but provide equivalent CLI flags for each interactive step (device selection, target selection, confirmations).

- Structured output: add `--output json` (or `--output yaml`) to emit machine-readable results (selected targets, MACs, status) for integration with monitoring or automation systems.

- Daemon mode / service: support running as a background service with logging and a PID file, plus a safe shutdown API that restores ARP tables and IP forwarding.

- Programmatic library API: expose core components (device listing, host discovery, ARP sending/restore) as a library crate behind a feature flag so other Rust programs can embed or test the functionality.

- Testing & CI: add unit and integration tests for parsing, device detection, and gateway detection; add a GitHub Actions workflow for linting (`cargo fmt`, `cargo clippy`) and building on multiple targets.

- Packaging & distribution: add distro packaging instructions (Deb/RPM), a `Makefile` or `install.sh` (already included) and optionally a small Docker image for testing in controlled lab environments.

- Security & audit: add safer defaults, better error handling, and auditability (explicit consent prompts, dry-run mode, and clear logging). Consider a feature to perform only passive scanning (no injection) to reduce risk.

If you'd like, I can start by implementing the CLI flags and a `--yes` non-interactive mode, adding JSON output, or scaffolding a small CI workflow—tell me which of these to prioritize.
