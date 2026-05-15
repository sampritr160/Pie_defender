import os
import sys
import time
import threading

from collections import defaultdict

sys.path.append(
    os.path.dirname(__file__)
)

from ryu.base import app_manager

from ryu.controller import ofp_event

from ryu.controller.handler import (
    MAIN_DISPATCHER,
    CONFIG_DISPATCHER,
    set_ev_cls
)

from ryu.ofproto import (
    ofproto_v1_3
)

from ryu.lib.packet import (
    packet,
    ethernet,
    ether_types
)

from mac_injection_module2 import (
    MACInjectionDetector2
)

from mitigation2 import (
    MitigationEngine2
)

from host_trust_engine import (
    HostTrustEngine
)

from behavioral_ml_engine import (
    BehavioralMLEngine
)

from cleanup_manager import (
    CleanupManager
)

from config import *


class PIEDefender3(app_manager.RyuApp):

    OFP_VERSIONS = [
        ofproto_v1_3.OFP_VERSION
    ]

    # =====================================================
    # INIT
    # =====================================================

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        self.mac_table = defaultdict(dict)

        self.logger.info(
            "INITIALIZING PIEDEFENDER3"
        )

        self.mac_detector = None

        self.trust_engine = None

        self.ml_engine = None

        self.cleanup_manager = None

        # =================================================
        # MAC DETECTOR
        # =================================================

        if ENABLE_MAC_DETECTOR:

            self.mac_detector = (
                MACInjectionDetector2()
            )

            self.logger.info(
                "MAC DETECTOR ENABLED"
            )

        # =================================================
        # TRUST ENGINE
        # =================================================

        if ENABLE_TRUST_ENGINE:

            self.trust_engine = (
                HostTrustEngine(
                    self.logger
                )
            )

            self.logger.info(
                "TRUST ENGINE ENABLED"
            )

        # =================================================
        # ML ENGINE
        # =================================================

        if ENABLE_BEHAVIORAL_ML:

            self.ml_engine = (
                BehavioralMLEngine(
                    self.logger
                )
            )

            self.logger.info(
                "BEHAVIORAL ML ENABLED"
            )

        # =================================================
        # MITIGATION
        # =================================================

        self.mitigator = (
            MitigationEngine2(
                self.logger
            )
        )

        # =================================================
        # CLEANUP
        # =================================================

        if ENABLE_TRUST_ENGINE:

            self.cleanup_manager = (
                CleanupManager(
                    self.logger,
                    self.trust_engine
                )
            )

            self.logger.info(
                "CLEANUP MANAGER ENABLED"
            )

        # =================================================
        # STATUS THREAD
        # =================================================

        threading.Thread(

            target=self._print_status_loop,

            daemon=True

        ).start()

    # =====================================================
    # SWITCH FEATURES
    # =====================================================

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions = [

            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        inst = [

            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(

            datapath=datapath,

            priority=0,

            match=match,

            instructions=inst
        )

        datapath.send_msg(mod)

        self.logger.info(
            "SWITCH CONNECTED | dpid=%s",
            datapath.id
        )

    # =====================================================
    # IGNORE
    # =====================================================

    def ignore_packet(self, eth):

        return eth.ethertype in (

            ether_types.ETH_TYPE_LLDP,

            ether_types.ETH_TYPE_IPV6
        )

    # =====================================================
    # ML EXECUTION
    # ONLY FOR TRUSTED HOSTS
    # =====================================================

    def _run_behavioral_ml(
        self,
        datapath,
        src,
        profile
    ):

        try:

            if not ENABLE_BEHAVIORAL_ML:
                return

            if self.ml_engine is None:
                return

            if profile is None:
                return

            # =================================================
            # FIRST TRUST CYCLE
            # INSTALL LONG FLOW ONLY
            # NO ML YET
            # =================================================

            if not profile.get(
                "ml_bootstrap_done",
                False
            ):

                profile[
                    "ml_bootstrap_done"
                ] = True

                profile[
                    "ml_last_check"
                ] = time.time()

                self.logger.info(
                    "ML BOOTSTRAP | mac=%s",
                    src
                )

                return

            current_time = time.time()

            last_check = profile.get(
                "ml_last_check",
                0
            )

            elapsed = (
                current_time
                - last_check
            )

            if elapsed < ML_RECHECK_INTERVAL:

                return

            profile[
                "ml_last_check"
            ] = current_time

            self.logger.info(
                "RUNNING ML ANALYSIS | mac=%s",
                src
            )

            ml_result = (
                self.ml_engine.predict_behavior(
                    profile
                )
            )

            if not isinstance(
                ml_result,
                dict
            ):

                self.logger.error(
                    "INVALID ML RESULT TYPE"
                )

                return

            # =================================================
            # ML ONLY UPDATES TRUST
            # =================================================

            self.trust_engine.apply_ml_result(
                src,
                ml_result
            )

            updated_profile = (
                self.trust_engine.get_profile(
                    src
                )
            )

            if updated_profile is None:
                return

            self.logger.warning(

                "ML RESULT | mac=%s probability=%.4f ml_state=%s trust=%.2f",

                src,

                updated_profile.get(
                    "ml_probability",
                    0.0
                ),

                updated_profile.get(
                    "ml_state",
                    "UNKNOWN"
                ),

                updated_profile.get(
                    "trust_score",
                    0.0
                )
            )

            # =================================================
            # BLOCK ONLY IF REALLY BLOCKED
            # =================================================

            if (
                updated_profile["state"]
                == STATE_BLOCKED
            ):

                self.logger.warning(
                    "ML BLOCKED HOST | mac=%s",
                    src
                )

                self.mitigator.install_mac_drop_rule(

                    datapath,

                    src,

                    hard_timeout=BLOCK_HARD_TIMEOUT
                )

        except Exception as e:

            self.logger.error(
                "ML EXECUTION FAILED | %s",
                e
            )

    # =====================================================
    # PACKET IN
    # =====================================================

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):

        try:

            msg = ev.msg

            datapath = msg.datapath

            parser = datapath.ofproto_parser

            ofproto = datapath.ofproto

            dpid = datapath.id

            in_port = msg.match["in_port"]

            pkt = packet.Packet(msg.data)

            eth = pkt.get_protocol(
                ethernet.ethernet
            )

            if eth is None:
                return

            if self.ignore_packet(eth):
                return

            src = eth.src

            dst = eth.dst

            self.logger.info(

                "PACKET_IN | dpid=%s src=%s dst=%s port=%s",

                dpid,

                src,

                dst,

                in_port
            )

            # =================================================
            # MAC LEARNING
            # =================================================

            self.mac_table[dpid][src] = (
                in_port
            )

            # =================================================
            # PROFILE MANAGEMENT
            # =================================================

            profile = None

            if ENABLE_TRUST_ENGINE:

                if not self.trust_engine.profile_exists(src):

                    self.trust_engine.create_profile(

                        src,

                        dpid,

                        in_port
                    )

                profile = (
                    self.trust_engine.update_profile(
                        src,
                        dst
                    )
                )

                if profile:

                    state = profile["state"]

                    # =====================================
                    # TRUST ENGINE ONLY HANDLES
                    # OBSERVATION + SUSPICIOUS
                    # =====================================

                    if state != STATE_TRUSTED:

                        if dst != "ff:ff:ff:ff:ff:ff":

                            self.trust_engine.reward_behavior(
                                src
                            )

                        # =================================
                        # UNKNOWN DESTINATION
                        # =================================

                        if (

                            dst != "ff:ff:ff:ff:ff:ff"

                            and dst not in self.mac_table[dpid]
                        ):

                            self.trust_engine.penalize_behavior(
                                src
                            )

            # =================================================
            # FORWARDING
            # =================================================

            if dst in self.mac_table[dpid]:

                out_port = (
                    self.mac_table[dpid][dst]
                )

                idle_timeout = (
                    OBS_IDLE_TIMEOUT
                )

                hard_timeout = (
                    OBS_HARD_TIMEOUT
                )

                # =============================================
                # TRUST STATE LOGIC
                # =============================================

                if ENABLE_TRUST_ENGINE:

                    profile = (
                        self.trust_engine.get_profile(
                            src
                        )
                    )

                    if profile:

                        state = profile["state"]

                        # =================================
                        # TRUSTED
                        # =================================

                        if state == STATE_TRUSTED:

                            self.trust_engine.reward_flow_refresh(
                                src
                            )

                            # =============================
                            # ML MODULE CONTROLS TRUSTED
                            # =============================

                            self._run_behavioral_ml(
                                datapath,
                                src,
                                profile
                            )

                            updated_profile = (
                                self.trust_engine.get_profile(
                                    src
                                )
                            )

                            if updated_profile:

                                state = (
                                    updated_profile["state"]
                                )

                            # =============================
                            # DOWNGRADED
                            # =============================

                            if state != STATE_TRUSTED:

                                self.logger.warning(

                                    "HOST DOWNGRADED | mac=%s new_state=%s trust=%.2f",

                                    src,

                                    state,

                                    updated_profile[
                                        "trust_score"
                                    ]
                                )

                            if state == STATE_BLOCKED:

                                return

                            idle_timeout = (
                                TRUSTED_IDLE_TIMEOUT
                            )

                            hard_timeout = (
                                TRUSTED_HARD_TIMEOUT
                            )

                        # =================================
                        # SUSPICIOUS
                        # =================================

                        elif state == STATE_SUSPICIOUS:

                            idle_timeout = (
                                SUSPICIOUS_IDLE_TIMEOUT
                            )

                            hard_timeout = (
                                SUSPICIOUS_HARD_TIMEOUT
                            )

                        # =================================
                        # BLOCKED
                        # =================================

                        elif state == STATE_BLOCKED:

                            self.logger.warning(
                                "BLOCKED HOST | mac=%s",
                                src
                            )

                            self.mitigator.install_mac_drop_rule(

                                datapath,

                                src,

                                hard_timeout=BLOCK_HARD_TIMEOUT
                            )

                            return

                # =============================================
                # INSTALL FLOW
                # =============================================

                self.logger.info(

                    "FLOW INSTALLED | src=%s dst=%s idle=%s hard=%s",

                    src,

                    dst,

                    idle_timeout,

                    hard_timeout
                )

                match = parser.OFPMatch(

                    in_port=in_port,

                    eth_src=src,

                    eth_dst=dst
                )

                actions = [

                    parser.OFPActionOutput(
                        out_port
                    )
                ]

                inst = [

                    parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS,
                        actions
                    )
                ]

                mod = parser.OFPFlowMod(

                    datapath=datapath,

                    priority=10,

                    match=match,

                    instructions=inst,

                    idle_timeout=idle_timeout,

                    hard_timeout=hard_timeout
                )

                datapath.send_msg(mod)

                self._send_packet(

                    datapath,

                    msg,

                    out_port
                )

            else:

                self._flood(

                    datapath,

                    msg,

                    in_port
                )

        except Exception as e:

            self.logger.error(
                "PACKET HANDLER FAILED | %s",
                e
            )

    # =====================================================
    # STATUS LOOP
    # =====================================================

    def _print_status_loop(self):

        while True:

            time.sleep(
                PROFILE_PRINT_INTERVAL
            )

            try:

                if ENABLE_TRUST_ENGINE:

                    self.trust_engine.apply_global_decay()

                    profiles = list(

                        self.trust_engine.host_profiles.keys()
                    )

                    for mac in profiles:

                        decision = (
                            self.trust_engine.should_cleanup_profile(
                                mac
                            )
                        )

                        if decision == "DELETE":

                            self.logger.warning(
                                "PROFILE CLEANUP | mac=%s",
                                mac
                            )

                            self.trust_engine.remove_profile(
                                mac
                            )

                        elif decision == "BLOCK":

                            self.logger.warning(
                                "LONG TERM BLOCK | mac=%s",
                                mac
                            )

                self.logger.info("=" * 80)

                self.logger.info(
                    "PIEDEFENDER STATUS"
                )

                self.logger.info("=" * 80)

                total = 0

                for dpid, macs in self.mac_table.items():

                    total += len(macs)

                self.logger.info(
                    "TOTAL MACS = %s",
                    total
                )

                if ENABLE_TRUST_ENGINE:

                    self.trust_engine.print_profiles()

            except Exception as e:

                self.logger.error(
                    "STATUS LOOP FAILED | %s",
                    e
                )

    # =====================================================
    # SEND PACKET
    # =====================================================

    def _send_packet(
        self,
        datapath,
        msg,
        out_port
    ):

        parser = datapath.ofproto_parser

        out = parser.OFPPacketOut(

            datapath=datapath,

            buffer_id=msg.buffer_id,

            in_port=msg.match["in_port"],

            actions=[

                parser.OFPActionOutput(
                    out_port
                )
            ],

            data=msg.data
        )

        datapath.send_msg(out)

    # =====================================================
    # FLOOD
    # =====================================================

    def _flood(
        self,
        datapath,
        msg,
        in_port
    ):

        parser = datapath.ofproto_parser

        ofproto = datapath.ofproto

        out = parser.OFPPacketOut(

            datapath=datapath,

            buffer_id=msg.buffer_id,

            in_port=in_port,

            actions=[

                parser.OFPActionOutput(
                    ofproto.OFPP_FLOOD
                )
            ],

            data=msg.data
        )

        datapath.send_msg(out)