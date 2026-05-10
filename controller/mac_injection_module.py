#!/usr/bin/env python3
"""
MAC Injection Detector Module
Implements Stage 1: MAC Injection Detection
Distinguishes between edge ports (hosts) and internal ports (switch-to-switch)
"""

class MACInjectionDetector:
    """
    Stage 1: MAC Injection Detection Module
    Correctly handles edge vs internal ports
    """
    
    def __init__(self, mac_threshold=3):
        """
        Initialize the detector
        
        Args:
            mac_threshold: Number of different MACs needed to classify as internal port
        """
        self.edge_ports = {}          # {(dpid, port): expected_mac} - host ports
        self.internal_ports = set()   # {(dpid, port)} - switch-to-switch ports
        self.blocked_ports = set()    # {(dpid, port)} - blocked due to injection
        self.port_mac_history = {}    # {(dpid, port): set(macs)} - for auto-detection
        self.mac_threshold = mac_threshold
    
    def mark_as_internal_port(self, dpid, port):
        """
        Manually mark a port as internal (switch-to-switch)
        
        Args:
            dpid: Switch DPID
            port: Port number
        """
        key = (dpid, port)
        if key not in self.internal_ports:
            self.internal_ports.add(key)
            # Remove from edge ports if it was there
            if key in self.edge_ports:
                del self.edge_ports[key]
            print(f"INTERNAL PORT MARKED: dpid={dpid}, port={port}")
    
    def mark_as_edge_port(self, dpid, port, mac):
        """
        Manually mark a port as edge (host)
        
        Args:
            dpid: Switch DPID
            port: Port number
            mac: Expected MAC address
        """
        key = (dpid, port)
        if key in self.internal_ports:
            self.internal_ports.remove(key)
        self.edge_ports[key] = mac
        print(f"EDGE PORT MARKED: dpid={dpid}, port={port}, mac={mac}")
    
    def _auto_detect_port_type(self, dpid, port, src_mac):
        """
        Automatically detect if port is internal based on MAC diversity
        
        Args:
            dpid: Switch DPID
            port: Port number
            src_mac: Source MAC address
        """
        key = (dpid, port)
        
        # Initialize history for this port
        if key not in self.port_mac_history:
            self.port_mac_history[key] = set()
        
        # Add this MAC to history
        self.port_mac_history[key].add(src_mac)
        
        # If we've seen threshold different MACs, mark as internal
        if len(self.port_mac_history[key]) >= self.mac_threshold:
            if key not in self.internal_ports:
                self.mark_as_internal_port(dpid, port)
                return True
        return False
    
    def is_edge_port(self, dpid, port):
        """Check if port is an edge port"""
        return (dpid, port) in self.edge_ports
    
    def is_internal_port(self, dpid, port):
        """Check if port is an internal port"""
        return (dpid, port) in self.internal_ports
    
    def is_blocked_port(self, dpid, port):
        """Check if port is blocked"""
        return (dpid, port) in self.blocked_ports
    
    def get_expected_mac(self, dpid, port):
        """Get expected MAC for an edge port"""
        return self.edge_ports.get((dpid, port), None)
    
    def process_packet(self, dpid, port, src_mac, packet_info=None):
        """
        Process a packet to detect MAC injection
        
        Args:
            dpid: Switch DPID
            port: Ingress port
            src_mac: Source MAC address
            packet_info: Optional dict with packet details (eth_type, dst_mac, etc.)
        
        Returns:
            (status, details): Status string and optional details
        """
        key = (dpid, port)
        
        # Check if port is blocked
        if self.is_blocked_port(dpid, port):
            return "BLOCKED", {"dpid": dpid, "port": port}
        
        # Auto-detect port type if not already classified
        port_detected = self._auto_detect_port_type(dpid, port, src_mac)
        
        # If port is internal, allow all MACs
        if self.is_internal_port(dpid, port):
            if port_detected:
                return "INTERNAL_PORT_AUTO_DETECTED", {"dpid": dpid, "port": port, "mac": src_mac}
            return "OK_INTERNAL", {"dpid": dpid, "port": port, "mac": src_mac}
        
        # Handle broadcast/multicast packets specially
        if packet_info:
            # Skip ARP packets for learning (they're normal)
            if packet_info.get('eth_type') == 0x0806:  # ARP
                # Still track for port type detection but don't enforce MAC consistency
                if not self.is_internal_port(dpid, port) and key not in self.edge_ports:
                    # First time seeing this port with ARP
                    self.edge_ports[key] = src_mac
                    return "EDGE_LEARNED_VIA_ARP", {"dpid": dpid, "port": port, "mac": src_mac}
                return "ARP_OK", {"dpid": dpid, "port": port, "mac": src_mac}
            
            # Skip broadcast packets
            dst_mac = packet_info.get('dst_mac', '')
            if dst_mac and (dst_mac.startswith('ff:ff:ff:ff:ff:ff') or 
                           dst_mac.startswith('01:00:5e') or
                           dst_mac.startswith('33:33')):
                return "BROADCAST_OK", {"dpid": dpid, "port": port, "mac": src_mac}
        
        # If port is not in edge_ports yet, learn it
        if key not in self.edge_ports:
            self.edge_ports[key] = src_mac
            return "EDGE_LEARNED", {"dpid": dpid, "port": port, "mac": src_mac}
        
        # Check for MAC change on edge port
        expected_mac = self.edge_ports[key]
        if expected_mac != src_mac:
            # MAC injection detected on edge port!
            old_mac = expected_mac
            self.blocked_ports.add(key)
            print(f"MAC INJECTION DETECTED: dpid={dpid}, port={port}, "
                  f"expected={old_mac}, got={src_mac}")
            return "INJECTION_DETECTED", {
                "dpid": dpid, 
                "port": port, 
                "expected_mac": old_mac, 
                "actual_mac": src_mac
            }
        
        # Everything normal
        return "OK", {"dpid": dpid, "port": port, "mac": src_mac}
    
    def unblock_port(self, dpid, port):
        """Unblock a previously blocked port"""
        key = (dpid, port)
        if key in self.blocked_ports:
            self.blocked_ports.remove(key)
            print(f"PORT UNBLOCKED: dpid={dpid}, port={port}")
            return True
        return False
    
    def reset_port(self, dpid, port):
        """Reset learning for a port"""
        key = (dpid, port)
        self.edge_ports.pop(key, None)
        self.internal_ports.discard(key)
        self.blocked_ports.discard(key)
        self.port_mac_history.pop(key, None)
        print(f"PORT RESET: dpid={dpid}, port={port}")
    
    def get_stats(self):
        """Get statistics about the detector"""
        return {
            "edge_ports": len(self.edge_ports),
            "internal_ports": len(self.internal_ports),
            "blocked_ports": len(self.blocked_ports),
            "monitored_ports": len(self.port_mac_history)
        }
    
    def print_status(self):
        """Print current status"""
        print("\n" + "="*60)
        print("MAC INJECTION DETECTOR STATUS")
        print("="*60)
        print(f"Edge Ports: {len(self.edge_ports)}")
        for (dpid, port), mac in self.edge_ports.items():
            print(f"  Switch {dpid}, Port {port}: {mac}")
        
        print(f"\nInternal Ports: {len(self.internal_ports)}")
        for dpid, port in self.internal_ports:
            print(f"  Switch {dpid}, Port {port}")
        
        print(f"\nBlocked Ports: {len(self.blocked_ports)}")
        for dpid, port in self.blocked_ports:
            print(f"  Switch {dpid}, Port {port}")
        
        print(f"\nPorts Being Monitored: {len(self.port_mac_history)}")
        for (dpid, port), macs in self.port_mac_history.items():
            print(f"  Switch {dpid}, Port {port}: {len(macs)} unique MACs")
        print("="*60 + "\n")