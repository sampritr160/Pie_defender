# =============================================================================
# PIEDEFENDER v2 SDN CONTROLLER - MAIN FILE
# Ryu SDN controller integrating Trust Engine, ML Engine, and Cleanup Manager
# Authority is determined by owner field set by _recalculate_state()
# BLOCKED hosts are checked FIRST and packets are dropped immediately
# =============================================================================

import os
import sys
import time
import threading
from collections import defaultdict

sys.path.append(os.path.dirname(__file__))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types

from config import *
from host_trust_engine import HostTrustEngine
from behavioral_ml_engine import BehavioralMLEngine
from cleanup_manager import CleanupManager


class PIEDefender3(app_manager.RyuApp):
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.mac_table = defaultdict(dict)
        self.datapaths = {}
        
        self.logger.info("=" * 60)
        self.logger.info("PIEDEFENDER v2 INITIALIZING")
        self.logger.info("=" * 60)
        
        if ENABLE_TRUST_ENGINE:
            self.trust_engine = HostTrustEngine(self.logger)
            self.logger.info("TRUST ENGINE ENABLED")
        
        if ENABLE_BEHAVIORAL_ML:
            self.ml_engine = BehavioralMLEngine(self.logger)
            if self.ml_engine.model_loaded:
                self.logger.info("BEHAVIORAL ML ENABLED")
            else:
                self.logger.warning("BEHAVIORAL ML DISABLED - MODEL NOT LOADED")
        
        if ENABLE_TRUST_ENGINE:
            self.cleanup_manager = CleanupManager(
                self.logger, self.trust_engine, mitigator=None, datapaths=self.datapaths
            )
            self.logger.info("CLEANUP MANAGER ENABLED")
        
        status_thread = threading.Thread(target=self._print_status_loop, daemon=True)
        status_thread.start()
        self.logger.info("STATUS MONITORING THREAD STARTED")
        self.logger.info("PIEDEFENDER v2 INITIALIZATION COMPLETE")
        self.logger.info("=" * 60)
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.datapaths[datapath.id] = datapath
        
        # Default flow: send all packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("SWITCH CONNECTED | dpid=%s", datapath.id)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            dpid = datapath.id
            in_port = msg.match["in_port"]
            
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)
            
            if eth is None:
                return
            
            if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
                return
            
            src = eth.src
            dst = eth.dst
            
            self.logger.info("PACKET_IN | dpid=%s src=%s dst=%s port=%s", dpid, src, dst, in_port)
            
            # =============================================================
            # CRITICAL: Check if source host is BLOCKED FIRST
            # Drop packet immediately without any processing
            # =============================================================
            if ENABLE_TRUST_ENGINE and self.trust_engine.profile_exists(src):
                profile_check = self.trust_engine.get_profile(src)
                if profile_check and profile_check.get("state") == STATE_BLOCKED:
                    self.logger.warning("BLOCKED HOST PACKET DROPPED | mac=%s", src)
                    return
            
            # Learn MAC
            self.mac_table[dpid][src] = in_port
            
            profile = None
            
            if ENABLE_TRUST_ENGINE:
                if not self.trust_engine.profile_exists(src):
                    self.trust_engine.create_profile(src, dpid, in_port)
                
                profile = self.trust_engine.update_profile_stats(src, dst)
                
                if profile:
                    state = profile["state"]
                    owner = profile.get("owner", "TRUST")
                    is_new_destination = 1 if dst not in profile.get("unique_destinations", set()) else 0
                    
                    # =====================================================
                    # REWARD/PENALTY ONLY WHEN OWNER == "TRUST"
                    # =====================================================
                    if owner == "TRUST":
                        if dst != "ff:ff:ff:ff:ff:ff":
                            self.trust_engine.reward_behavior(src)
                        
                        if dst != "ff:ff:ff:ff:ff:ff" and dst not in self.mac_table[dpid]:
                            self.trust_engine.penalize_behavior(src)
                    
                    # =====================================================
                    # ML ANALYSIS ONLY WHEN OWNER == "ML" AND STATE TRUSTED
                    # =====================================================
                    if owner == "ML" and state == STATE_TRUSTED and ENABLE_BEHAVIORAL_ML:
                        self.trust_engine.reward_flow_refresh(src)
                        profile = self.trust_engine.get_profile(src)
                        
                        if profile and self.ml_engine and self.ml_engine.model_loaded:
                            now = time.time()
                            last_check = profile.get("ml_last_check", 0)
                            
                            if not profile.get("ml_bootstrap_done", False):
                                profile["ml_bootstrap_done"] = True
                                profile["ml_last_check"] = now
                                self.logger.info("ML BOOTSTRAP | mac=%s (first trusted cycle)", src)
                            elif now - last_check >= ML_RECHECK_INTERVAL:
                                profile["ml_last_check"] = now
                                ml_result = self.ml_engine.predict_behavior(profile, is_new_destination)
                                self.trust_engine.apply_ml_result(src, ml_result)
            
            # =============================================================
            # FLOW INSTALLATION
            # =============================================================
            if dst in self.mac_table[dpid]:
                out_port = self.mac_table[dpid][dst]
                idle_timeout = OBS_IDLE_TIMEOUT
                hard_timeout = OBS_HARD_TIMEOUT
                
                if ENABLE_TRUST_ENGINE and profile:
                    state = profile["state"]
                    if state == STATE_TRUSTED:
                        idle_timeout = TRUSTED_IDLE_TIMEOUT
                        hard_timeout = TRUSTED_HARD_TIMEOUT
                    elif state == STATE_SUSPICIOUS:
                        idle_timeout = SUSPICIOUS_IDLE_TIMEOUT
                        hard_timeout = SUSPICIOUS_HARD_TIMEOUT
                    elif state == STATE_BLOCKED:
                        self.logger.warning("BLOCKED HOST FLOW SKIPPED | mac=%s", src)
                        return
                
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
                actions = [parser.OFPActionOutput(out_port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                
                mod = parser.OFPFlowMod(
                    datapath=datapath, priority=10, match=match, instructions=inst,
                    idle_timeout=idle_timeout, hard_timeout=hard_timeout
                )
                datapath.send_msg(mod)
                
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                    actions=actions, data=msg.data
                )
                datapath.send_msg(out)
                
            else:
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                    actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)], data=msg.data
                )
                datapath.send_msg(out)
                
        except Exception as e:
            self.logger.error("PACKET HANDLER FAILED | %s", e)
    
    def _print_status_loop(self):
        while True:
            time.sleep(PROFILE_PRINT_INTERVAL)
            try:
                if ENABLE_TRUST_ENGINE:
                    self.trust_engine.apply_global_decay()
                    total_macs = sum(len(macs) for macs in self.mac_table.values())
                    self.logger.info("=" * 80)
                    self.logger.info("PIEDEFENDER STATUS")
                    self.logger.info("=" * 80)
                    self.logger.info("TOTAL MACS = %d", total_macs)
                    self.logger.info("=" * 80)
                    self.trust_engine.print_profiles()
            except Exception as e:
                self.logger.error("STATUS LOOP FAILED | %s", e)