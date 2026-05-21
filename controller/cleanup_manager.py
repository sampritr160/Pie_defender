# =============================================================================
# CLEANUP MANAGER MODULE
# ONLY deletes or temporarily blocks inactive hosts.
# Does NOT apply decay (decay is handled by Trust Engine)
# Does NOT downgrade TRUSTED hosts (state transitions handled by Trust Engine)
# =============================================================================

import time
import threading
from config import *

class CleanupManager:
    
    def __init__(self, logger, trust_engine, mitigator=None, datapaths=None):
        self.logger = logger
        self.trust_engine = trust_engine
        self.mitigator = mitigator
        self.datapaths = datapaths
        
        cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        cleanup_thread.start()
        self.logger.info("CLEANUP MANAGER THREAD STARTED")
    
    def _cleanup_loop(self):
        while True:
            time.sleep(30)
            try:
                self.cleanup_profiles()
            except Exception as e:
                self.logger.error("CLEANUP LOOP FAILED | %s", e)
    
    def _install_block_rule(self, mac, datapath, duration_seconds=TEMPORARY_BLOCK_DURATION):
        """Install OpenFlow drop rule for blocked host directly"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Create match for source MAC
            match = parser.OFPMatch(eth_src=mac)
            instructions = []  # No actions = drop
            
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=100,
                match=match,
                instructions=instructions,
                hard_timeout=duration_seconds,
                idle_timeout=0,
                buffer_id=ofproto.OFP_NO_BUFFER
            )
            datapath.send_msg(mod)
            
            # Also block destination MAC
            match_dst = parser.OFPMatch(eth_dst=mac)
            mod_dst = parser.OFPFlowMod(
                datapath=datapath,
                priority=100,
                match=match_dst,
                instructions=instructions,
                hard_timeout=duration_seconds,
                idle_timeout=0,
                buffer_id=ofproto.OFP_NO_BUFFER
            )
            datapath.send_msg(mod_dst)
            
            self.logger.warning("BLOCK RULE INSTALLED | mac=%s duration=%ds", mac, duration_seconds)
            return True
        except Exception as e:
            self.logger.error("BLOCK RULE INSTALL FAILED | mac=%s error=%s", mac, e)
            return False
    
    def _temporary_block_host(self, mac, duration_seconds=TEMPORARY_BLOCK_DURATION):
        """Temporary block host - install block rules on all switches"""
        if self.datapaths is None or len(self.datapaths) == 0:
            self.logger.warning("TEMPORARY BLOCK | no datapaths available")
            return
        
        block_success = False
        for datapath in self.datapaths.values():
            if self._install_block_rule(mac, datapath, duration_seconds):
                block_success = True
        
        if block_success:
            # Mark profile for deletion when block expires
            profile = self.trust_engine.get_profile(mac)
            if profile:
                profile["block_until"] = time.time() + duration_seconds
                profile["state"] = STATE_BLOCKED
                self.logger.warning("TEMPORARY BLOCK ACTIVE | mac=%s duration=%ds", mac, duration_seconds)
        else:
            self.logger.error("TEMPORARY BLOCK FAILED | mac=%s", mac)
    
    def _delete_profile(self, mac):
        """Delete profile completely - will be recreated if host appears again"""
        try:
            self.trust_engine.remove_profile(mac)
            self.logger.warning("PROFILE DELETED | mac=%s", mac)
        except Exception as e:
            self.logger.error("PROFILE DELETE FAILED | mac=%s error=%s", mac, e)
    
    def cleanup_profiles(self):
        now = time.time()
        deleted_count = 0
        blocked_count = 0
        
        for mac, profile in list(self.trust_engine.host_profiles.items()):
            try:
                state = profile.get("state", STATE_OBSERVATION)
                
                # =============================================================
                # Handle BLOCKED state - delete after block expires
                # =============================================================
                if state == STATE_BLOCKED:
                    block_until = profile.get("block_until", 0)
                    if now >= block_until and block_until > 0:
                        # Clear the switch rule flag before deletion
                        self.trust_engine.remove_switch_block_flag(mac)
                        self._delete_profile(mac)
                        deleted_count += 1
                        self.logger.info("BLOCK EXPIRED - PROFILE DELETED | mac=%s", mac)
                    continue
                
                # =============================================================
                # SKIP TRUSTED HOSTS - Cleanup manager does NOT downgrade
                # Decay and state transitions are handled by Trust Engine
                # =============================================================
                if state == STATE_TRUSTED:
                    continue
                
                # =============================================================
                # Handle inactive OBSERVATION/SUSPICIOUS hosts
                # =============================================================
                last_seen = profile.get("last_seen", now)
                elapsed = now - last_seen
                
                if state == STATE_OBSERVATION:
                    timeout = OBSERVATION_PROFILE_TIMEOUT
                elif state == STATE_SUSPICIOUS:
                    timeout = SUSPICIOUS_PROFILE_TIMEOUT
                else:
                    timeout = OBSERVATION_PROFILE_TIMEOUT
                
                if elapsed < timeout:
                    continue
                
                # Get cleanup decision from trust engine
                decision = self.trust_engine.should_cleanup_profile(mac)
                
                if decision == "DELETE":
                    self._delete_profile(mac)
                    deleted_count += 1
                elif decision == "BLOCK":
                    self._temporary_block_host(mac, TEMPORARY_BLOCK_DURATION)
                    blocked_count += 1
                    
            except Exception as e:
                self.logger.error("PROFILE CLEANUP CHECK FAILED | mac=%s error=%s", mac, e)
        
        if deleted_count > 0 or blocked_count > 0:
            self.logger.info("CLEANUP SUMMARY | deleted=%d blocked=%d", deleted_count, blocked_count)# =============================================================================
# CLEANUP MANAGER MODULE
# ONLY deletes or temporarily blocks inactive hosts.
# Does NOT apply decay (decay is handled by Trust Engine)
# Does NOT downgrade TRUSTED hosts (state transitions handled by Trust Engine)
# =============================================================================

import time
import threading
from config import *

class CleanupManager:
    
    def __init__(self, logger, trust_engine, mitigator=None, datapaths=None):
        self.logger = logger
        self.trust_engine = trust_engine
        self.mitigator = mitigator
        self.datapaths = datapaths
        
        cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        cleanup_thread.start()
        self.logger.info("CLEANUP MANAGER THREAD STARTED")
    
    def _cleanup_loop(self):
        while True:
            time.sleep(30)
            try:
                self.cleanup_profiles()
            except Exception as e:
                self.logger.error("CLEANUP LOOP FAILED | %s", e)
    
    def _install_block_rule(self, mac, datapath, duration_seconds=TEMPORARY_BLOCK_DURATION):
        """Install OpenFlow drop rule for blocked host directly"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Create match for source MAC
            match = parser.OFPMatch(eth_src=mac)
            instructions = []  # No actions = drop
            
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=100,
                match=match,
                instructions=instructions,
                hard_timeout=duration_seconds,
                idle_timeout=0,
                buffer_id=ofproto.OFP_NO_BUFFER
            )
            datapath.send_msg(mod)
            
            # Also block destination MAC
            match_dst = parser.OFPMatch(eth_dst=mac)
            mod_dst = parser.OFPFlowMod(
                datapath=datapath,
                priority=100,
                match=match_dst,
                instructions=instructions,
                hard_timeout=duration_seconds,
                idle_timeout=0,
                buffer_id=ofproto.OFP_NO_BUFFER
            )
            datapath.send_msg(mod_dst)
            
            self.logger.warning("BLOCK RULE INSTALLED | mac=%s duration=%ds", mac, duration_seconds)
            return True
        except Exception as e:
            self.logger.error("BLOCK RULE INSTALL FAILED | mac=%s error=%s", mac, e)
            return False
    
    def _temporary_block_host(self, mac, duration_seconds=TEMPORARY_BLOCK_DURATION):
        """Temporary block host - install block rules on all switches"""
        if self.datapaths is None or len(self.datapaths) == 0:
            self.logger.warning("TEMPORARY BLOCK | no datapaths available")
            return
        
        block_success = False
        for datapath in self.datapaths.values():
            if self._install_block_rule(mac, datapath, duration_seconds):
                block_success = True
        
        if block_success:
            # Mark profile for deletion when block expires
            profile = self.trust_engine.get_profile(mac)
            if profile:
                profile["block_until"] = time.time() + duration_seconds
                profile["state"] = STATE_BLOCKED
                self.logger.warning("TEMPORARY BLOCK ACTIVE | mac=%s duration=%ds", mac, duration_seconds)
        else:
            self.logger.error("TEMPORARY BLOCK FAILED | mac=%s", mac)
    
    def _delete_profile(self, mac):
        """Delete profile completely - will be recreated if host appears again"""
        try:
            self.trust_engine.remove_profile(mac)
            self.logger.warning("PROFILE DELETED | mac=%s", mac)
        except Exception as e:
            self.logger.error("PROFILE DELETE FAILED | mac=%s error=%s", mac, e)
    
    def cleanup_profiles(self):
        now = time.time()
        deleted_count = 0
        blocked_count = 0
        
        for mac, profile in list(self.trust_engine.host_profiles.items()):
            try:
                state = profile.get("state", STATE_OBSERVATION)
                
                # =============================================================
                # Handle BLOCKED state - delete after block expires
                # =============================================================
                if state == STATE_BLOCKED:
                    block_until = profile.get("block_until", 0)
                    if now >= block_until and block_until > 0:
                        self._delete_profile(mac)
                        deleted_count += 1
                        self.logger.info("BLOCK EXPIRED - PROFILE DELETED | mac=%s", mac)
                    continue
                
                # =============================================================
                # SKIP TRUSTED HOSTS - Cleanup manager does NOT downgrade
                # Decay and state transitions are handled by Trust Engine
                # =============================================================
                if state == STATE_TRUSTED:
                    continue
                
                # =============================================================
                # Handle inactive OBSERVATION/SUSPICIOUS hosts
                # =============================================================
                last_seen = profile.get("last_seen", now)
                elapsed = now - last_seen
                
                if state == STATE_OBSERVATION:
                    timeout = OBSERVATION_PROFILE_TIMEOUT
                elif state == STATE_SUSPICIOUS:
                    timeout = SUSPICIOUS_PROFILE_TIMEOUT
                else:
                    timeout = OBSERVATION_PROFILE_TIMEOUT
                
                if elapsed < timeout:
                    continue
                
                # Get cleanup decision from trust engine
                decision = self.trust_engine.should_cleanup_profile(mac)
                
                if decision == "DELETE":
                    self._delete_profile(mac)
                    deleted_count += 1
                elif decision == "BLOCK":
                    self._temporary_block_host(mac, TEMPORARY_BLOCK_DURATION)
                    blocked_count += 1
                    
            except Exception as e:
                self.logger.error("PROFILE CLEANUP CHECK FAILED | mac=%s error=%s", mac, e)
        
        if deleted_count > 0 or blocked_count > 0:
            self.logger.info("CLEANUP SUMMARY | deleted=%d blocked=%d", deleted_count, blocked_count)
