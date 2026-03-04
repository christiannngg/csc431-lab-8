#!/usr/bin/env python3
"""
Encrypted Traffic Detector - Info Sec Lab
Sniffs packets, calculates Shannon entropy, auto-blocks high-entropy sources via UFW.
"""

import math
import subprocess
import logging
from collections import defaultdict, Counter
from scapy.all import sniff, Raw, IP, TCP

# --- Config ---
ENTROPY_THRESHOLD = 7.0       # bits/byte — above this = likely encrypted
MIN_PAYLOAD_BYTES = 32        # ignore tiny payloads (unreliable entropy)
BLOCK_AFTER_FLAGS = 3         # how many flags before UFW deny rule fires
MONITOR_PORT = 9999           # port to watch
LOG_FILE = "detector.log"

# --- Logging Setup ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

# --- State ---
ip_flag_counter = defaultdict(int)
blocked_ips = set()


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
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
    """Add a UFW deny rule for the given IP."""
    if ip in blocked_ips:
        return
    print(f"  [BLOCK] Issuing: sudo ufw deny from {ip}")
    result = subprocess.run(
        ["sudo", "ufw", "deny", "from", ip],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        blocked_ips.add(ip)
        logging.info(f"BLOCKED | IP={ip} | UFW rule added")
        print(f"  [BLOCK] UFW rule added for {ip}")
    else:
        print(f"  [ERROR] UFW failed: {result.stderr.strip()}")


def process_packet(pkt):
    """Callback for each sniffed packet."""
    # Only care about TCP packets with a payload on our monitored port
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return
    if pkt[TCP].dport != MONITOR_PORT and pkt[TCP].sport != MONITOR_PORT:
        return

    src_ip = pkt[IP].src
    payload = bytes(pkt[Raw].load)

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
    print("  Encrypted Traffic Detector")
    print(f"  Monitoring port {MONITOR_PORT} | Entropy threshold: {ENTROPY_THRESHOLD}")
    print(f"  Block after {BLOCK_AFTER_FLAGS} flags | Min payload: {MIN_PAYLOAD_BYTES}B")
    print("=" * 55)
    print("  Sniffing... (Ctrl+C to stop)\n")

    sniff(
        iface="lo0",   # macOS loopback — change to eth0/ens33 on Linux VM
        filter=f"tcp port {MONITOR_PORT}",
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    main()