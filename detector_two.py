#!/usr/bin/env python3
"""
Encrypted Traffic Detector - Info Sec Lab
Uses tcpdump (via sudo) for capture, Python for entropy analysis + UFW blocking.
"""

import math
import subprocess
import logging
import sys
from collections import defaultdict, Counter

# --- Config ---
ENTROPY_THRESHOLD = 7.0
MIN_PAYLOAD_BYTES = 32
BLOCK_AFTER_FLAGS = 3
MONITOR_PORT = 9999
LOG_FILE = "detector.log"
IFACE = "lo"  # loopback for local testing

# --- Logging ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

# --- State ---
ip_flag_counter = defaultdict(int)
blocked_ips = set()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def block_ip(ip: str):
    if ip in blocked_ips:
        return
    print(f"  [BLOCK] Issuing: sudo ufw deny from {ip}")
    result = subprocess.run(
        ["sudo", "/usr/sbin/ufw", "deny", "from", ip],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        blocked_ips.add(ip)
        logging.info(f"BLOCKED | IP={ip} | UFW rule added")
        print(f"  [BLOCK] UFW rule added for {ip}")
    else:
        print(f"  [ERROR] UFW failed: {result.stderr.strip()}")


def process_hex_payload(src_ip: str, hex_str: str):
    """Parse hex payload from tcpdump and analyze entropy."""
    # tcpdump -XX outputs hex like: 0x0000: 4500 0034 ...
    # Extract only the hex bytes
    hex_bytes = hex_str.replace(" ", "").replace(":", "")
    try:
        raw = bytes.fromhex(hex_bytes)
    except ValueError:
        return

    # Strip first 54 bytes (14 Ethernet + 20 IP + 20 TCP headers)
    payload = raw[54:]

    if len(payload) < MIN_PAYLOAD_BYTES:
        return

    entropy = shannon_entropy(payload)
    status = "HIGH-ENTROPY" if entropy >= ENTROPY_THRESHOLD else "normal"

    print(f"  [{status}] src={src_ip} | payload={len(payload)}B | entropy={entropy:.3f}")
    logging.info(f"{status} | IP={src_ip} | bytes={len(payload)} | entropy={entropy:.3f}")

    if entropy >= ENTROPY_THRESHOLD:
        ip_flag_counter[src_ip] += 1
        count = ip_flag_counter[src_ip]
        print(f"  [FLAG] {src_ip} flagged {count}/{BLOCK_AFTER_FLAGS} times")
        if count >= BLOCK_AFTER_FLAGS:
            block_ip(src_ip)


def main():
    print("=" * 55)
    print("  Encrypted Traffic Detector (tcpdump mode)")
    print(f"  Monitoring port {MONITOR_PORT} | Threshold: {ENTROPY_THRESHOLD}")
    print(f"  Block after {BLOCK_AFTER_FLAGS} flags | Iface: {IFACE}")
    print("=" * 55)
    print("  Sniffing... (Ctrl+C to stop)\n")

    # Launch tcpdump with hex output, no DNS resolution
    cmd = [
        "sudo", "/usr/bin/tcpdump",
        "-i", IFACE,
        "-XX",          # full hex+ascii dump
        "-n",           # no DNS lookups
        "-l",           # line-buffered output
        f"tcp port {MONITOR_PORT}"
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    current_src = None
    hex_accumulator = []

    try:
        for line in proc.stdout:
            line = line.rstrip()

            # New packet header line — looks like:
            # 12:34:56.789 IP 127.0.0.1.54321 > 127.0.0.1.9999: ...
            if "IP " in line and f".{MONITOR_PORT}" in line:
                # Process previous packet if we have one
                if current_src and hex_accumulator:
                    process_hex_payload(current_src, "".join(hex_accumulator))

                # Extract source IP
                try:
                    parts = line.split("IP ")[1].split(" > ")[0]
                    current_src = ".".join(parts.split(".")[:4])
                except IndexError:
                    current_src = "unknown"

                hex_accumulator = []

            # Hex data lines start with a tab and 0x
            elif line.strip().startswith("0x") and current_src:
                # Format: "\t0x0000:  4500 0034 ..."
                # Take only the hex portion (before the ASCII section)
                parts = line.strip().split("  ")
                if len(parts) >= 2:
                    hex_part = parts[1].replace(" ", "")
                    hex_accumulator.append(hex_part)

    except KeyboardInterrupt:
        print("\n[*] Stopping detector...")
        proc.terminate()
        print(f"[*] Log saved to {LOG_FILE}")


if __name__ == "__main__":
    main()
