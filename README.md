# Network-based Intrusion Detection and Prevention System (NIDPS)

## Overview

This project implements a Network-based Intrusion Detection and Prevention System (NIDPS) using Python. The system monitors network traffic, detects malicious activities through signature and anomaly-based detection techniques, logs intrusions, blocks attackers, and provides a CLI for management. It is designed to detect port scanning, OS fingerprinting, and other network attacks.

## Features

- **Network Traffic Monitoring**: Capture and analyze TCP packets.
- **Intrusion Detection**:
  - **Port Scanning Detection**: Flags IPs scanning >6 ports in 15 seconds or sequential ports.
  - **OS Fingerprinting Detection**: Detects IPs sending 5+ unique TCP flag combinations in 20 seconds.
- **Intrusion Prevention**: Automatically block malicious IPs using `iptables`.
- **Logging**: Detailed logs in `ids.log`.
- **CLI Interface**: Manage IDS, view traffic, logs, and blocked IPs.

## Prerequisites

- Linux OS (for `iptables` integration)
- Python 3.x
- `hping3` (for attack simulation)
- Root/sudo privileges (required for packet sniffing and `iptables`)

## Libraries Used

- `scapy`: Packet sniffing and manipulation.
- `colorama` & `pyfiglet`: CLI interface styling.
- `subprocess`: Execute system commands (e.g., `iptables`).

## Installation

1. **Set up the virtual environment**:

   ```bash
   chmod +x script.sh
   ./script.sh  # Installs dependencies from requirements.txt
   ```

2. **Install `hping3`**:
   ```bash
   sudo apt-get install hping3
   ```

## Workflow

1. **Traffic Capture**: Uses `scapy` to sniff TCP packets.
2. **Detection Engine**:
   - **Anomaly Detection**: Track ports per IP over time windows.
   - **Signature Detection**: Flag abnormal TCP flag combinations.
3. **Prevention**: Block detected IPs via `iptables`.
4. **Logging**: Record intrusions in `ids.log`.
5. **CLI**: Manage the system interactively.

## Execution Steps

1. **Run the NIDPS CLI** (as root):

   ```bash
   sudo python3 cli.py
   ```

2. **Use the CLI Menu**:

   - Select `1` to start the IDS.
   - Use other options to view traffic, logs, or manage blocked IPs.

3. **Simulate Attacks** (in a separate terminal):
   ```bash
   python3 attack_script.py
   ```
   Follow prompts to generate port scans, SYN floods, or normal traffic.

## Attacks Explained

### 1. Port Scanning

- **Purpose**: Identify open ports on a target.
- **Detection**:
  - **Anomaly-Based**: >6 unique ports from an IP in 15 seconds.
  - **Sequential**: 6+ consecutive ports (e.g., port 80, 81, 82...).

### 2. OS Fingerprinting

- **Purpose**: Determine the target's OS using TCP flag variations.
- **Detection**: 5+ unique flag combinations (e.g., SYN, SYN+ACK) from an IP in 20 seconds.

### 3. SYN Flood

- **Purpose**: Overwhelm a target with SYN packets to exhaust resources.
- **Simulation**: `attack_script.py` sends multiple SYN packets to a port.

## Notes

- Ensure the target IP in `attack_script.py` matches your environment.
- Logs are saved in `ids.log`.
- Blocked IPs can be managed via the CLI or `iptables` directly.
