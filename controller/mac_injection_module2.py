import time

class MACInjectionDetector2:

    def __init__(self, mac_threshold=3, block_timeout=60, violation_threshold=2, 
                 port_status_wait_packets=10, port_status_allowed_macs=1):
        """      
        Args:
            mac_threshold: Number of MACs to auto-detect as internal port (default: 3)
            block_timeout: Seconds before auto-unblocking a port (default: 60)
            violation_threshold: Number of violations before blocking (default: 3)
            port_status_wait_packets: Number of packets to wait after port-status event (default: 10)
            port_status_allowed_macs: Max unique MACs allowed during verification (default: 1)
        """
        self.edge_ports = {}
        self.internal_ports = set()
        self.blocked_ports = set()
        self.blocked_ports_expiry = {}
        self.port_mac_history = {}
        self.port_violations = {}
        
        # PDF Algorithm 2: Port-Status Verification
        self.pending_ports = {}  # key -> {"temp_macs": set(), "packets_received": int, "start_time": float}
        self.port_status_wait_packets = port_status_wait_packets
        self.port_status_allowed_macs = port_status_allowed_macs
        
        self.mac_threshold = mac_threshold
        self.block_timeout = block_timeout
        self.violation_threshold = violation_threshold
        self.last_cleanup = time.time()

    def _cleanup_expired_blocks(self):
        """Remove expired blocked ports and reset their violation counts"""
        now = time.time()
        expired_ports = []
        
        for key, expiry_time in self.blocked_ports_expiry.items():
            if now >= expiry_time:
                expired_ports.append(key)
        
        for key in expired_ports:
            if key in self.blocked_ports:
                self.blocked_ports.remove(key)
                self.blocked_ports_expiry.pop(key, None)
                if key in self.port_violations:
                    self.port_violations[key] = 0

    def _cleanup_stale_pending_ports(self, timeout_seconds=30):
        """Remove pending verification entries that are too old"""
        now = time.time()
        stale_keys = []
        for key, data in self.pending_ports.items():
            if now - data["start_time"] > timeout_seconds:
                stale_keys.append(key)
        
        for key in stale_keys:
            del self.pending_ports[key]

    def mark_as_internal_port(self, dpid, port):
        key = (dpid, port)
        if key not in self.internal_ports:
            self.internal_ports.add(key)
            if key in self.edge_ports:
                del self.edge_ports[key]
            if key in self.port_violations:
                self.port_violations[key] = 0
            # Remove from pending verification if any
            if key in self.pending_ports:
                del self.pending_ports[key]

    def mark_as_edge_port(self, dpid, port, mac):
        key = (dpid, port)
        if key in self.internal_ports:
            self.internal_ports.remove(key)
        self.edge_ports[key] = mac
        if key in self.port_violations:
            self.port_violations[key] = 0
        # Remove from pending verification if any
        if key in self.pending_ports:
            del self.pending_ports[key]

    def _auto_detect_port_type(self, dpid, port, src_mac):
        key = (dpid, port)

        if key not in self.port_mac_history:
            self.port_mac_history[key] = set()

        self.port_mac_history[key].add(src_mac)

        if len(self.port_mac_history[key]) >= self.mac_threshold:
            if key not in self.internal_ports:
                self.mark_as_internal_port(dpid, port)
                return True
        return False

    def is_edge_port(self, dpid, port):
        return (dpid, port) in self.edge_ports

    def is_internal_port(self, dpid, port):
        return (dpid, port) in self.internal_ports

    def is_blocked_port(self, dpid, port):
        # Run cleanup periodically
        now = time.time()
        if now - self.last_cleanup >= 10:
            self._cleanup_expired_blocks()
            self._cleanup_stale_pending_ports()
            self.last_cleanup = now
        
        return (dpid, port) in self.blocked_ports

    def get_expected_mac(self, dpid, port):
        return self.edge_ports.get((dpid, port), None)

    def notify_port_status(self, dpid, port):
        """
        Algorithm 2: Handle OFPT_PORT_STATUS message
        Called by controller when port status changes (down/up)
        
        This puts the port in verification mode - we collect packets
        before updating the main mapping table.
        """
        key = (dpid, port)
        
        # Enter verification mode
        self.pending_ports[key] = {
            "temp_macs": set(),
            "packets_received": 0,
            "start_time": time.time()
        }
        
        # Do NOT delete main mapping yet! Keep it for now.
        # Original mapping stays until verification completes
        
        print(f"[DEBUG] Port {dpid}:{port} entered verification mode. Will wait for {self.port_status_wait_packets} packets.")
        return True

    def unblock_port(self, dpid, port):
        """Manually unblock a port and reset its state"""
        key = (dpid, port)
        if key in self.blocked_ports:
            self.blocked_ports.remove(key)
            self.blocked_ports_expiry.pop(key, None)
            if key in self.port_violations:
                self.port_violations[key] = 0
            # Remove from pending verification if any
            if key in self.pending_ports:
                del self.pending_ports[key]
            return True
        return False

    def reset_port(self, dpid, port):
        """
        Force reset a port (clear all mappings)
        This is called when a host is removed or manually reset
        """
        key = (dpid, port)
        self.edge_ports.pop(key, None)
        self.internal_ports.discard(key)
        self.blocked_ports.discard(key)
        self.blocked_ports_expiry.pop(key, None)
        self.port_mac_history.pop(key, None)
        self.port_violations.pop(key, None)
        # Remove from pending verification if any
        if key in self.pending_ports:
            del self.pending_ports[key]

    def get_stats(self):
        return {
            "edge_ports": len(self.edge_ports),
            "internal_ports": len(self.internal_ports),
            "blocked_ports": len(self.blocked_ports),
            "monitored_ports": len(self.port_mac_history),
            "pending_verifications": len(self.pending_ports),
            "block_timeout": self.block_timeout,
            "violation_threshold": self.violation_threshold,
            "port_status_wait_packets": self.port_status_wait_packets,
            "port_status_allowed_macs": self.port_status_allowed_macs
        }

    def get_mac_table(self):
        mac_table = {}
        for (dpid, port), mac in self.edge_ports.items():
            if dpid not in mac_table:
                mac_table[dpid] = {}
            mac_table[dpid][mac] = port
        return mac_table

    def process_packet(self, dpid, port, src_mac, packet_info=None):
        """
        Process a packet and detect MAC injection attacks.
        
        PDF Algorithm 2 integration:
        - If port is in pending verification mode, collect packets first
        - Only update main mapping after verification completes
        
        Returns:
            Tuple of (status, details)
        """
        key = (dpid, port)

        # Run periodic cleanup
        if time.time() - self.last_cleanup >= 10:
            self._cleanup_expired_blocks()
            self._cleanup_stale_pending_ports()
            self.last_cleanup = time.time()

        # Check if port is already blocked
        if self.is_blocked_port(dpid, port):
            return "BLOCKED", {"dpid": dpid, "port": port}

        # =============================================================
        # PDF Algorithm 2: Port-Status Verification
        # =============================================================
        if key in self.pending_ports:
            pending_data = self.pending_ports[key]
            pending_data["packets_received"] += 1
            pending_data["temp_macs"].add(src_mac)
            
            # Check if we have received enough packets
            if pending_data["packets_received"] >= self.port_status_wait_packets:
                # Verification complete - analyze results
                unique_macs_count = len(pending_data["temp_macs"])
                
                if unique_macs_count <= self.port_status_allowed_macs:
                    # Legitimate: Only 1 MAC seen (or within allowed limit)
                    # Update main mapping with the MAC
                    new_mac = list(pending_data["temp_macs"])[0] if unique_macs_count > 0 else src_mac
                    self.edge_ports[key] = new_mac
                    
                    # Remove from pending
                    del self.pending_ports[key]
                    
                    print(f"[DEBUG] Port {dpid}:{port} verification PASSED. Unique MACs: {unique_macs_count}. Updated mapping to {new_mac}")
                    
                    # Return as normal edge learned
                    return "EDGE_LEARNED", {
                        "dpid": dpid, "port": port, "mac": new_mac,
                        "verification": "passed"
                    }
                else:
                    # Attack detected: Multiple MACs seen during verification
                    # Block the port immediately
                    self.blocked_ports.add(key)
                    self.blocked_ports_expiry[key] = time.time() + self.block_timeout
                    
                    # Remove from pending
                    del self.pending_ports[key]
                    
                    print(f"[DEBUG] Port {dpid}:{port} verification FAILED! Unique MACs: {unique_macs_count} > {self.port_status_allowed_macs}")
                    
                    return "INJECTION_DETECTED", {
                        "dpid": dpid,
                        "port": port,
                        "macs_seen": list(pending_data["temp_macs"]),
                        "unique_macs": unique_macs_count,
                        "allowed_macs": self.port_status_allowed_macs,
                        "block_duration": self.block_timeout,
                        "message": f"Port blocked for {self.block_timeout} seconds - multiple MACs during port-status verification"
                    }
            else:
                # Still collecting packets
                return "VERIFICATION_PENDING", {
                    "dpid": dpid,
                    "port": port,
                    "packets_received": pending_data["packets_received"],
                    "packets_needed": self.port_status_wait_packets,
                    "unique_macs_so_far": len(pending_data["temp_macs"])
                }

        # =============================================================
        # Normal processing (not in verification mode)
        # =============================================================
        
        # Auto-detect port type based on MAC count
        port_detected = self._auto_detect_port_type(dpid, port, src_mac)

        # Handle internal ports (trunk links to other switches)
        if self.is_internal_port(dpid, port):
            if port_detected:
                return "INTERNAL_PORT_AUTO_DETECTED", {
                    "dpid": dpid, "port": port, "mac": src_mac
                }
            return "OK_INTERNAL", {
                "dpid": dpid, "port": port, "mac": src_mac
            }

        # Handle ARP packets specially
        if packet_info:
            if packet_info.get('eth_type') == 0x0806:  # ARP
                if not self.is_internal_port(dpid, port) and key not in self.edge_ports:
                    self.edge_ports[key] = src_mac
                    return "EDGE_LEARNED_VIA_ARP", {
                        "dpid": dpid, "port": port, "mac": src_mac
                    }
                return "ARP_OK", {
                    "dpid": dpid, "port": port, "mac": src_mac
                }

            # Handle broadcast/multicast (always allowed)
            dst_mac = packet_info.get('dst_mac', '')
            if dst_mac and (
                dst_mac.startswith('ff:ff:ff:ff:ff:ff') or
                dst_mac.startswith('01:00:5e') or
                dst_mac.startswith('33:33')
            ):
                return "BROADCAST_OK", {
                    "dpid": dpid, "port": port, "mac": src_mac
                }

        # First time seeing this edge port - learn the MAC
        if key not in self.edge_ports:
            self.edge_ports[key] = src_mac
            return "EDGE_LEARNED", {
                "dpid": dpid, "port": port, "mac": src_mac
            }

        # Check for MAC injection (different MAC on expected edge port)
        expected_mac = self.edge_ports[key]
        if expected_mac != src_mac:
            # Increment violation counter for this port
            self.port_violations[key] = self.port_violations.get(key, 0) + 1
            violations = self.port_violations[key]
            
            # Graduated response based on violation count
            if violations < self.violation_threshold:
                # Warning only - not blocked yet
                return "WARNING", {
                    "dpid": dpid,
                    "port": port,
                    "expected_mac": expected_mac,
                    "actual_mac": src_mac,
                    "violation_count": violations,
                    "threshold": self.violation_threshold,
                    "message": f"Warning {violations}/{self.violation_threshold} - will block on next violation"
                }
            else:
                # Block the port with timeout
                self.blocked_ports.add(key)
                self.blocked_ports_expiry[key] = time.time() + self.block_timeout
                
                return "INJECTION_DETECTED", {
                    "dpid": dpid,
                    "port": port,
                    "expected_mac": expected_mac,
                    "actual_mac": src_mac,
                    "violation_count": violations,
                    "block_duration": self.block_timeout,
                    "message": f"Port blocked for {self.block_timeout} seconds"
                }

        # All good - same MAC as expected
        # Reset violation count on successful matching packet
        if key in self.port_violations and self.port_violations[key] > 0:
            self.port_violations[key] = max(0, self.port_violations[key] - 1)
        
        return "OK", {
            "dpid": dpid, "port": port, "mac": src_mac
        }