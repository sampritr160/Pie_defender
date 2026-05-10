class MACInjectionDetector2:

    def __init__(self, mac_threshold=3):
        self.edge_ports = {}
        self.internal_ports = set()
        self.blocked_ports = set()
        self.port_mac_history = {}
        self.mac_threshold = mac_threshold

    def mark_as_internal_port(self, dpid, port):
        key = (dpid, port)
        if key not in self.internal_ports:
            self.internal_ports.add(key)
            if key in self.edge_ports:
                del self.edge_ports[key]

    def mark_as_edge_port(self, dpid, port, mac):
        key = (dpid, port)
        if key in self.internal_ports:
            self.internal_ports.remove(key)
        self.edge_ports[key] = mac

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
        return (dpid, port) in self.blocked_ports

    def get_expected_mac(self, dpid, port):
        return self.edge_ports.get((dpid, port), None)

    def process_packet(self, dpid, port, src_mac, packet_info=None):
        key = (dpid, port)

        if self.is_blocked_port(dpid, port):
            return "BLOCKED", {"dpid": dpid, "port": port}

        port_detected = self._auto_detect_port_type(dpid, port, src_mac)

        if self.is_internal_port(dpid, port):
            if port_detected:
                return "INTERNAL_PORT_AUTO_DETECTED", {
                    "dpid": dpid, "port": port, "mac": src_mac
                }
            return "OK_INTERNAL", {
                "dpid": dpid, "port": port, "mac": src_mac
            }

        if packet_info:
            if packet_info.get('eth_type') == 0x0806:
                if not self.is_internal_port(dpid, port) and key not in self.edge_ports:
                    self.edge_ports[key] = src_mac
                    return "EDGE_LEARNED_VIA_ARP", {
                        "dpid": dpid, "port": port, "mac": src_mac
                    }
                return "ARP_OK", {
                    "dpid": dpid, "port": port, "mac": src_mac
                }

            dst_mac = packet_info.get('dst_mac', '')
            if dst_mac and (
                dst_mac.startswith('ff:ff:ff:ff:ff:ff') or
                dst_mac.startswith('01:00:5e') or
                dst_mac.startswith('33:33')
            ):
                return "BROADCAST_OK", {
                    "dpid": dpid, "port": port, "mac": src_mac
                }

        if key not in self.edge_ports:
            self.edge_ports[key] = src_mac
            return "EDGE_LEARNED", {
                "dpid": dpid, "port": port, "mac": src_mac
            }

        expected_mac = self.edge_ports[key]
        if expected_mac != src_mac:
            self.blocked_ports.add(key)
            return "INJECTION_DETECTED", {
                "dpid": dpid,
                "port": port,
                "expected_mac": expected_mac,
                "actual_mac": src_mac
            }

        return "OK", {
            "dpid": dpid, "port": port, "mac": src_mac
        }

    def unblock_port(self, dpid, port):
        key = (dpid, port)
        if key in self.blocked_ports:
            self.blocked_ports.remove(key)
            return True
        return False

    def reset_port(self, dpid, port):
        key = (dpid, port)
        self.edge_ports.pop(key, None)
        self.internal_ports.discard(key)
        self.blocked_ports.discard(key)
        self.port_mac_history.pop(key, None)

    def get_stats(self):
        return {
            "edge_ports": len(self.edge_ports),
            "internal_ports": len(self.internal_ports),
            "blocked_ports": len(self.blocked_ports),
            "monitored_ports": len(self.port_mac_history)
        }

    def get_mac_table(self):
        mac_table = {}
        for (dpid, port), mac in self.edge_ports.items():
            if dpid not in mac_table:
                mac_table[dpid] = {}
            mac_table[dpid][mac] = port
        return mac_table
