import os
import sys
import time
import joblib
import threading
import warnings
from collections import defaultdict

# Ignore sklearn warning about feature names
warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names*"
)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp

from mac_injection_module2 import MACInjectionDetector2
from dos_detection2 import DoSFeatureExtractor2
from mitigation2 import MitigationEngine2


# 0 = off, 1 = MAC only, 2 = DoS only, 3 = both
PIEDEFENDER_MODE = 1


class PIEDefender2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_table = defaultdict(dict)
        self.traffic_log = []

        if PIEDEFENDER_MODE in [1, 3]:
            self.mac_detector = MACInjectionDetector2()

        if PIEDEFENDER_MODE in [2, 3]:
            ml_dir = os.path.join(os.path.dirname(__file__), '..', 'ml')
            self.scaler = joblib.load(os.path.join(ml_dir, "piedefender_scaler2.pkl"))
            self.svm_model = joblib.load(os.path.join(ml_dir, "piedefender_svm_model2.pkl"))
            self.dos_detector = DoSFeatureExtractor2()
            self.last_svm_check = {}

        self.mitigator = MitigationEngine2(self.logger)

        threading.Thread(target=self._print_mac_table, daemon=True).start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions
        )]

        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        ))

        self.logger.info(f"SWITCH CONNECTED dpid={datapath.id}")

    # =========================================================================
    # NEW: Port-Status Handler for PDF Algorithm 2
    # This is the ONLY addition to this file
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        """Handle port status changes (up/down) for MAC injection detection"""
        msg = ev.msg
        datapath = msg.datapath
        port_no = msg.desc.port_no
        reason = msg.reason
        
        # Only process if MAC detection is enabled
        if PIEDEFENDER_MODE in [1, 3] and hasattr(self, 'mac_detector'):
            # Notify MAC detector about port status change
            self.mac_detector.notify_port_status(datapath.id, port_no)
            
            # Log the event for debugging
            reason_str = {0: "ADD", 1: "DELETE", 2: "MODIFY"}.get(reason, "UNKNOWN")
            self.logger.info(f"PORT STATUS | dpid={datapath.id} port={port_no} reason={reason_str}")
            
            # If port is deleted, also remove from MAC table
            if reason == 1:  # DELETE
                if datapath.id in self.mac_table:
                    # Remove all MACs associated with this port
                    macs_to_remove = [mac for mac, p in self.mac_table[datapath.id].items() if p == port_no]
                    for mac in macs_to_remove:
                        del self.mac_table[datapath.id][mac]
                        self.logger.info(f"MAC REMOVED | dpid={datapath.id} mac={mac} port={port_no} (port deleted)")

    def _log_traffic(self, dpid, src, dst, in_port, action):
        log_entry = (
            f"{time.time():.2f} | dpid={dpid} | src={src} | "
            f"dst={dst} | port={in_port} | action={action}"
        )
        self.traffic_log.append(log_entry)
        self.logger.info(log_entry)

    def _print_mac_table(self):
        while True:
            time.sleep(15)
            self.logger.info("\n" + "=" * 60)
            self.logger.info(
                f"MAC TABLE | Switches: {len(self.mac_table)}"
            )
            self.logger.info("=" * 60)

            total_macs = 0
            for dpid, macs in self.mac_table.items():
                self.logger.info(f"Switch {dpid} ({len(macs)} MACs):")
                for mac, port in macs.items():
                    self.logger.info(f"  {mac} -> Port {port}")
                total_macs += len(macs)

            self.logger.info(f"TOTAL MACs: {total_macs}")
            self.logger.info("=" * 60 + "\n")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None or eth.ethertype in (
            ether_types.ETH_TYPE_LLDP,
            ether_types.ETH_TYPE_IPV6
        ):
            return

        src = eth.src
        dst = eth.dst

        self._log_traffic(dpid, src, dst, in_port, "PACKET_IN")

        # MAC injection detection
        if PIEDEFENDER_MODE in [1, 3]:
            status, details = self.mac_detector.process_packet(
                dpid, in_port, src,
                {"eth_type": eth.ethertype, "dst_mac": dst}
            )

            # Handle different status codes
            if status == "INJECTION_DETECTED":
                self.logger.error(
                    f"MAC INJECTION BLOCKED | dpid={dpid} port={in_port}"
                )
                self.mitigator.install_drop_rule(datapath, in_port)
                return
            elif status == "BLOCKED":
                return
            elif status == "VERIFICATION_PENDING":
                # PDF Algorithm 2: Port is in verification mode
                # Drop packet temporarily until verification completes
                self.logger.debug(
                    f"VERIFICATION PENDING | dpid={dpid} port={in_port} "
                    f"packets={details.get('packets_received', 0)}/{details.get('packets_needed', 10)}"
                )
                return  # Drop packet during verification
            elif status == "WARNING":
                # Log warning but don't block yet (graduated response)
                self.logger.warning(
                    f"MAC WARNING | dpid={dpid} port={in_port} "
                    f"expected={details.get('expected_mac')} actual={details.get('actual_mac')} "
                    f"violation={details.get('violation_count')}/{details.get('threshold')}"
                )
                # Continue processing? No - drop the suspicious packet
                return
            # Other statuses: OK, EDGE_LEARNED, OK_INTERNAL, etc. -> continue

        # Learn MAC address
        if src not in self.mac_table[dpid]:
            self.mac_table[dpid][src] = in_port

        # DoS detection
        if PIEDEFENDER_MODE in [2, 3]:
            packet_data = {}

            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                packet_data['src_ip'] = ip_pkt.src
                packet_data['dst_ip'] = ip_pkt.dst

                tcp_pkt = pkt.get_protocol(tcp.tcp)
                udp_pkt = pkt.get_protocol(udp.udp)

                if tcp_pkt:
                    packet_data['src_port'] = tcp_pkt.src_port
                    packet_data['dst_port'] = tcp_pkt.dst_port
                elif udp_pkt:
                    packet_data['src_port'] = udp_pkt.src_port
                    packet_data['dst_port'] = udp_pkt.dst_port

            self.dos_detector.update(dpid, src, dst, in_port, packet_data)

            key = (dpid, src, in_port)
            now = time.time()

            if now - self.last_svm_check.get(key, 0) >= 2.0:
                self.last_svm_check[key] = now

                features = self.dos_detector.extract_features(
                    dpid, src, dst, in_port
                )

                if features and len(features) == 5:
                    X = self.scaler.transform([features])
                    prediction = int(self.svm_model.predict(X)[0])

                    if prediction == 1:
                        self.logger.error(
                            f"DoS ATTACK BLOCKED | dpid={dpid} src={src}"
                        )
                        self.mitigator.install_drop_rule(datapath, in_port)
                        return

        # Forward traffic
        if dst in self.mac_table[dpid]:
            out_port = self.mac_table[dpid][dst]

            self.logger.info(
                f"INSTALLING FLOW: {src}->{dst} via port {out_port}"
            )

            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src,
                eth_dst=dst
            )
            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions
            )]

            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=10,
                match=match,
                instructions=inst,
                idle_timeout=30,
                buffer_id=msg.buffer_id,
                flags=ofproto.OFPFF_SEND_FLOW_REM
            )
            datapath.send_msg(flow_mod)

            if PIEDEFENDER_MODE in [2, 3]:
                self.dos_detector.record_flow_mod(
                    dpid, src, dst, in_port
                )

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                datapath.send_msg(parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=[parser.OFPActionOutput(out_port)],
                    data=msg.data
                ))
        else:
            self._flood(datapath, msg, in_port)

    def _flood(self, datapath, msg, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)
