# spoofer

Warning: This project implements ARP spoofing techniques. Use only in controlled, legal environments (lab networks you own or explicitly have permission to test). Misuse may be illegal and harmful.

## Overview
spoofer is a small Rust tool that discovers devices on a local network and performs ARP spoofing against selected targets. The program is interactive and built around these core components:

- Packet capture & ARP spoofing: [`arp_spoof::start_arp_spoofing`](src/arp_spoof.rs) — implementation and helpers in [src/arp_spoof.rs](src/arp_spoof.rs). Key symbols:
  - [`arp_spoof::Target`](src/arp_spoof.rs)
  - [`arp_spoof::get_interface_mac`](src/arp_spoof.rs)
  - [`arp_spoof::get_interface_ip`](src/arp_spoof.rs)
  - [`arp_spoof::get_mac`](src/arp_spoof.rs)
  - [`arp_spoof::spoof`](src/arp_spoof.rs)
  - [`arp_spoof::send_arp`](src/arp_spoof.rs)
  - [`arp_spoof::restore_arp`](src/arp_spoof.rs)

- Network device enumeration: [`devices::get_network_devices`](src/devices.rs) and gateway discovery [`devices::get_linux_gateway_ip`](src/devices.rs) implemented in [src/devices.rs](src/devices.rs). Primary types:
  - [`devices::NetworkDevice`](src/devices.rs)

- CLI & interaction: helper functions in [src/cli.rs](src/cli.rs):
  - [`cli::select_device`](src/cli.rs)
  - [`cli::get_local_ip`](src/cli.rs)
  - [`cli::scan_ips`](src/cli.rs)
  - [`cli::select_ips`](src/cli.rs)
  - [`cli::prompt_retry`](src/cli.rs)

- Application entrypoint: [src/main.rs](src/main.rs) (`main`) coordinates discovery, selection, and launching the spoofing via [`arp_spoof::start_arp_spoofing`](src/arp_spoof.rs).

## Files
- [Cargo.toml](Cargo.toml)
- [.gitignore](.gitignore)
- [src/main.rs](src/main.rs)
- [src/cli.rs](src/cli.rs)
- [src/devices.rs](src/devices.rs)
- [src/arp_spoof.rs](src/arp_spoof.rs)

## Build
This is a standard Rust project. In the repository root run:

```sh
cargo build --release
```