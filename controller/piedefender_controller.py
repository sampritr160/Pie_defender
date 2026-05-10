import os
import sys
sys.path.append(os.path.dirname(__file__))

import time
import joblib
import threading
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types

from mac_injection_module import MACInjectionDetector
from dos_detection import DoSFeatureExtractor
from mitigation import MitigationEngine


class PIEDefender(app_manager.RyuApp):
    """
    PIEDefender SDN Controller

    Stage-1: MAC Injection Detection
    Stage-2: DoS Detection (SVM)
    Stage-3: Mitigation
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # =================================================
        # CORE SDN — store MULTIPLE MACs per port
        # =================================================
        self.mac_to_port = defaultdict(lambda: defaultdict(set))

        # ================= STAGE-1 =================
        self.mac_guard = MACInjectionDetector()

        # ================= STAGE-2 =================
        self.dos_extractor = DoSFeatureExtractor()

        base_dir = os.path.dirname(__file__)
        self.scaler = joblib.load(
            os.path.join(base_dir, "../ml/piedefender_scaler.pkl")
        )
        self.svm_model = joblib.load(
            os.path.join(base_dir, "../ml/piedefender_svm_model.pkl")
        )

        self.last_svm_check = {}
        self.SVM_INTERVAL = 2.0

        # -------- SVM SAFETY GATE --------
        self.MIN_PACKETS = 25
        self.MIN_RPI = 5.0
        self.MIN_DURATION = 3.0

        # ================= STAGE-3 =================
        self.mitigator = MitigationEngine(self.logger)

        # ========= PERIODIC MAC TABLE PRINTER =========
        threading.Thread(
            target=self._print_mac_table_periodically,
            daemon=True
        ).start()

    # =====================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # table-miss → controller
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

        self.logger.info("SWITCH CONNECTED dpid=%s", datapath.id)

    # =====================================================

    def ignore_packet(self, eth):
        return eth.ethertype in (
            ether_types.ETH_TYPE_LLDP,
            ether_types.ETH_TYPE_IPV6
        )

    # =====================================================
    # PACKET-IN HANDLER
    # =====================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser

        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None or self.ignore_packet(eth):
            return

        src = eth.src
        dst = eth.dst

        packet_info = {
            "eth_type": eth.ethertype,
            "dst_mac": eth.dst
        }

        # ================= STAGE-1 =================
        status, _ = self.mac_guard.process_packet(
            dpid, in_port, src, packet_info
        )

        if status == "INJECTION_DETECTED":
            self.logger.error(
                "MAC INJECTION ATTACK | dpid=%s port=%s",
                dpid, in_port
            )
            self.mitigator.install_drop_rule(datapath, in_port)
            return

        elif status == "BLOCKED":
            return

        # ---- LOG EVERY MAC LEARNING (THIS WAS MISSING) ----
        if src not in self.mac_to_port[dpid][in_port]:
            self.mac_to_port[dpid][in_port].add(src)
            self.logger.info(
                "[STAGE-1] Learned MAC %s on dpid=%s port=%s",
                src, dpid, in_port
            )

        # ================= STAGE-2 =================
        self.dos_extractor.update(dpid, src, dst, in_port)

        now = time.time()
        key = (dpid, src, in_port)
        self.last_svm_check.setdefault(key, now)

        if now - self.last_svm_check[key] >= self.SVM_INTERVAL:
            self.last_svm_check[key] = now

            features = self.dos_extractor.extract_features(
                dpid, src, dst, in_port
            )
            if features is None:
                return

            rpi, rfm, pirf, pfsp, _ = features

            if pfsp < self.MIN_PACKETS:
                return
            if rpi < self.MIN_RPI:
                return
            if pirf < self.MIN_DURATION:
                return

            X = self.scaler.transform([features])
            prediction = int(self.svm_model.predict(X)[0])

            if prediction == 1:
                self.logger.error(
                    "DoS ATTACK DETECTED | dpid=%s src=%s",
                    dpid, src
                )
                self.mitigator.install_drop_rule(datapath, in_port)
                return

        # ================= NORMAL SDN =================
        if dst in self._get_mac_port(dpid):
            out_port = self._get_mac_port(dpid)[dst]

            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src,
                eth_dst=dst
            )

            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions
            )]

            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath,
                priority=10,
                match=match,
                instructions=inst,
                idle_timeout=30
            ))

            self.send_packet(datapath, msg, out_port)
        else:
            self.flood(datapath, msg, in_port)

    # =====================================================

    def _get_mac_port(self, dpid):
        """Return first port for each MAC (normal switching)"""
        mapping = {}
        for port, macs in self.mac_to_port[dpid].items():
            for mac in macs:
                mapping[mac] = port
        return mapping

    # =====================================================

    def _print_mac_table_periodically(self):
        while True:
            time.sleep(5)

            self.logger.info("========== STAGE-1 MAC TABLE ==========")
            total = 0

            for dpid, ports in self.mac_to_port.items():
                self.logger.info("Switch %s:", dpid)
                for port, macs in ports.items():
                    for mac in macs:
                        self.logger.info("  Port %s -> %s", port, mac)
                    total += len(macs)

            self.logger.info("TOTAL MACs LEARNED: %s", total)
            self.logger.info("======================================")

    # =====================================================

    def send_packet(self, datapath, msg, out_port):
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'],
            actions=[parser.OFPActionOutput(out_port)],
            data=msg.data
        ))

    def flood(self, datapath, msg, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)],
            data=msg.data
        ))
