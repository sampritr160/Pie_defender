# =============================================================================
# HOST TRUST ENGINE MODULE
# Decay applies to ALL hosts every 30 seconds regardless of activity
# EXCEPT when trust is in protected range (73-78) to prevent oscillation
# Minimum reward of 0.1 prevents trust from freezing at 100
# Ownership transfer from ML to TRUST resets trust to 50
# =============================================================================

import time
import math
from config import *

class HostTrustEngine:
    
    def __init__(self, logger):
        self.logger = logger
        self.host_profiles = {}
    
    # =========================================================================
    # PROFILE HELPERS
    # =========================================================================
    
    def profile_exists(self, mac):
        return mac in self.host_profiles
    
    def get_profile(self, mac):
        return self.host_profiles.get(mac)
    
    def remove_profile(self, mac):
        if mac in self.host_profiles:
            del self.host_profiles[mac]
            self.logger.warning("PROFILE REMOVED | mac=%s", mac)
    
    def _clamp_trust(self, trust):
        if trust > MAX_TRUST_SCORE:
            return MAX_TRUST_SCORE
        if trust < MIN_TRUST_SCORE:
            return MIN_TRUST_SCORE
        return trust
    
    # =========================================================================
    # CREATE PROFILE
    # =========================================================================
    
    def create_profile(self, mac, dpid, port):
        now = time.time()
        
        self.host_profiles[mac] = {
            "mac": mac,
            "dpid": dpid,
            "port": port,
            "trust_score": INITIAL_TRUST,
            "state": STATE_OBSERVATION,
            "owner": "TRUST",
            "first_seen": now,
            "last_seen": now,
            "last_decay_time": now,
            "last_packet_time": now,
            "packet_count": 0,
            "successful_replies": 0,
            "failed_requests": 0,
            "flow_refresh_count": 0,
            "unique_destinations": set(),
            "destination_counts": {},
            "ml_probability": 0.0,
            "ml_probability_history": [],
            "ml_last_check": 0,
            "under_ml_control": False,
            "ml_bootstrap_done": False,
            "block_until": 0,
            "packets_per_second": 0.0,
            "bytes_per_second": 0.0,
            "avg_packet_size": 800.0,
            "interarrival_mean": 0.0,
            "interarrival_std": 0.0,
            "burstiness": 0.0,
            "destination_growth_rate": 0.0,
            "destination_entropy": 0.0,
            "flow_miss_rate": 0.0,
            "mac_churn_rate": 0.0,
            "controller_load_impact": 0.0,
            "syn_ratio": 0.2,
            "icmp_ratio": 0.05,
            "udp_ratio": 0.2,
            "recent_pps": [],
            "inactive_cycles": 0
        }
        
        self.logger.info("PROFILE CREATED | mac=%s trust=%.2f state=%s owner=TRUST", mac, INITIAL_TRUST, STATE_OBSERVATION)
        return self.host_profiles[mac]
    
    # =========================================================================
    # UPDATE PROFILE STATISTICS
    # =========================================================================
    
    def update_profile_stats(self, mac, dst_mac, protocol_flags=None):
        if mac not in self.host_profiles:
            return None
        
        profile = self.host_profiles[mac]
        now = time.time()
        
        elapsed = now - profile.get("last_packet_time", now)
        if elapsed <= 0:
            elapsed = 0.001
        
        profile["packet_count"] += 1
        profile["last_seen"] = now
        profile["last_packet_time"] = now
        profile["inactive_cycles"] = 0
        profile["unique_destinations"].add(dst_mac)
        profile["destination_counts"][dst_mac] = profile["destination_counts"].get(dst_mac, 0) + 1
        
        instant_pps = 1.0 / elapsed
        profile["recent_pps"].append(instant_pps)
        if len(profile["recent_pps"]) > STATS_WINDOW:
            profile["recent_pps"].pop(0)
        
        avg_pps = sum(profile["recent_pps"]) / len(profile["recent_pps"])
        profile["packets_per_second"] = avg_pps
        profile["bytes_per_second"] = avg_pps * 800
        profile["interarrival_mean"] = elapsed
        profile["interarrival_std"] = elapsed * 0.15
        profile["burstiness"] = min(1.0, avg_pps / HIGH_PPS_THRESHOLD)
        
        host_age = now - profile["first_seen"]
        if host_age > 0:
            profile["destination_growth_rate"] = len(profile["unique_destinations"]) / host_age
        else:
            profile["destination_growth_rate"] = 0
        
        total_dests = sum(profile["destination_counts"].values())
        entropy = 0.0
        for count in profile["destination_counts"].values():
            if total_dests > 0:
                p = count / total_dests
                entropy -= p * math.log2(p) if p > 0 else 0
        profile["destination_entropy"] = entropy
        
        if profile["packet_count"] > 0:
            profile["flow_miss_rate"] = profile["flow_refresh_count"] / profile["packet_count"]
        
        profile["controller_load_impact"] = profile["packets_per_second"] * max(1.0, len(profile["unique_destinations"]))
        profile["mac_churn_rate"] = len(profile["unique_destinations"]) * 0.1
        
        if protocol_flags:
            if protocol_flags.get("syn"):
                profile["syn_ratio"] = 0.8
            if protocol_flags.get("icmp"):
                profile["icmp_ratio"] = 0.8
            if protocol_flags.get("udp"):
                profile["udp_ratio"] = 0.8
        
        return profile
    
    # =========================================================================
    # REWARD BEHAVIOR (ONLY when owner == "TRUST")
    # Formula: delta_trust = TRUST_LEARNING_RATE * (1 - trust/100)
    # Minimum reward of MIN_TRUST_REWARD (0.1) prevents stall at high trust
    # =========================================================================
    
    def reward_behavior(self, mac):
        if mac not in self.host_profiles:
            return
        
        profile = self.host_profiles[mac]
        
        # ONLY reward if owner is TRUST (not ML)
        if profile.get("owner") != "TRUST":
            self.logger.debug("SKIP REWARD | mac=%s owner=%s (not TRUST)", mac, profile.get("owner"))
            return
        
        old_trust = profile["trust_score"]
        
        # Calculate reward with minimum threshold
        delta_trust = TRUST_LEARNING_RATE * (1 - (old_trust / 100.0))
        if delta_trust < MIN_TRUST_REWARD:
            delta_trust = MIN_TRUST_REWARD
        
        profile["successful_replies"] += 1
        profile["trust_score"] += delta_trust
        profile["trust_score"] = self._clamp_trust(profile["trust_score"])
        
        self.logger.info("TRUST REWARD | mac=%s delta=%.4f trust=%.2f->%.2f owner=TRUST", 
                         mac, delta_trust, old_trust, profile["trust_score"])
        
        self._recalculate_state(mac)
    
    # =========================================================================
    # PENALIZE BEHAVIOR (ONLY when owner == "TRUST")
    # =========================================================================
    
    def penalize_behavior(self, mac):
        if mac not in self.host_profiles:
            return
        
        profile = self.host_profiles[mac]
        
        # ONLY penalize if owner is TRUST (not ML)
        if profile.get("owner") != "TRUST":
            self.logger.debug("SKIP PENALTY | mac=%s owner=%s (not TRUST)", mac, profile.get("owner"))
            return
        
        profile["failed_requests"] += 1
        
        old_trust = profile["trust_score"]
        penalty = FAILED_REQUEST_PENALTY * max(0.2, old_trust / 100.0)
        
        profile["trust_score"] -= penalty
        profile["trust_score"] = self._clamp_trust(profile["trust_score"])
        
        self.logger.warning("TRUST PENALTY | mac=%s penalty=%.2f trust=%.2f->%.2f owner=TRUST", 
                            mac, penalty, old_trust, profile["trust_score"])
        
        self._recalculate_state(mac)
    
    # =========================================================================
    # FLOW REFRESH REWARD
    # =========================================================================
    
    def reward_flow_refresh(self, mac):
        if mac not in self.host_profiles:
            return
        self.host_profiles[mac]["flow_refresh_count"] += 1
    
    # =========================================================================
    # APPLY ML RESULT (called by controller when owner is ML)
    # ML provides probability. Trust Engine applies adjustment.
    # =========================================================================
    
    def apply_ml_result(self, mac, ml_result):
        if mac not in self.host_profiles:
            return
        
        profile = self.host_profiles[mac]
        probability = ml_result["probability"]
        
        # Store ML probability and history
        profile["ml_probability"] = probability
        profile["ml_probability_history"].append(probability)
        if len(profile["ml_probability_history"]) > 10:
            profile["ml_probability_history"].pop(0)
        
        profile["ml_last_check"] = time.time()
        
        old_trust = profile["trust_score"]
        
        # Calculate ML adjustment based on probability
        if probability < ML_TRUST_INCREASE_THRESHOLD:
            ml_adjustment = ML_TRUST_INCREASE_REWARD * (1 - probability)
            trust_action = "INCREASE"
        elif probability > ML_TRUST_DECREASE_THRESHOLD:
            ml_adjustment = -ML_TRUST_DECREASE_PENALTY * (probability - 0.7)
            trust_action = "DECREASE"
        else:
            ml_adjustment = 0
            trust_action = "NEUTRAL"
        
        # Apply ML adjustment
        profile["trust_score"] += ml_adjustment
        profile["trust_score"] = self._clamp_trust(profile["trust_score"])
        
        self.logger.warning(
            "ML TRUST UPDATE | mac=%s ml_prob=%.4f action=%s ml_adj=%.4f trust=%.2f->%.2f owner=ML",
            mac, probability, trust_action, ml_adjustment, old_trust, profile["trust_score"]
        )
        
        self._recalculate_state(mac)
    
    # =========================================================================
    # APPLY GLOBAL DECAY - APPLIES TO ALL HOSTS
    # EXCEPT when trust is in protected range (73-78) to prevent oscillation
    # Decay happens every TRUST_DECAY_INTERVAL (30 seconds)
    # =========================================================================
    
    def apply_global_decay(self):
        now = time.time()
        decay_applied = 0
        decay_skipped = 0
        
        for mac, profile in list(self.host_profiles.items()):
            # Skip blocked hosts
            if profile["state"] == STATE_BLOCKED:
                continue
            
            trust = profile["trust_score"]
            
            # CRITICAL FIX: Skip decay if trust is in protected range (73-78)
            # This prevents oscillation between TRUSTED and OBSERVATION
            if DECAY_PROTECTION_LOWER <= trust <= DECAY_PROTECTION_UPPER:
                self.logger.debug("DECAY SKIPPED | mac=%s trust=%.2f (protected range %d-%d)", 
                                  mac, trust, DECAY_PROTECTION_LOWER, DECAY_PROTECTION_UPPER)
                decay_skipped += 1
                continue
            
            # Check decay interval
            elapsed = now - profile.get("last_decay_time", now)
            if elapsed < TRUST_DECAY_INTERVAL:
                continue
            
            old_trust = trust
            
            # Apply decay
            profile["trust_score"] -= TRUST_DECAY_RATE
            profile["trust_score"] = self._clamp_trust(profile["trust_score"])
            profile["last_decay_time"] = now
            
            owner = profile.get("owner", "TRUST")
            self.logger.info("TRUST DECAY | mac=%s owner=%s decay=%.2f trust=%.2f->%.2f", 
                             mac, owner, TRUST_DECAY_RATE, old_trust, profile["trust_score"])
            
            decay_applied += 1
            self._recalculate_state(mac)
        
        if decay_applied > 0 or decay_skipped > 0:
            self.logger.debug("DECAY SUMMARY | applied=%d skipped=%d (protected range)", decay_applied, decay_skipped)
    
    # =========================================================================
    # SHOULD CLEANUP PROFILE (for cleanup manager)
    # =========================================================================
    
    def should_cleanup_profile(self, mac):
        if mac not in self.host_profiles:
            return False
        
        profile = self.host_profiles[mac]
        inactivity = time.time() - profile["last_seen"]
        
        # Get timeout based on state
        if profile["state"] == STATE_OBSERVATION:
            timeout = OBSERVATION_PROFILE_TIMEOUT
        elif profile["state"] == STATE_TRUSTED:
            timeout = TRUSTED_PROFILE_TIMEOUT
        elif profile["state"] == STATE_SUSPICIOUS:
            timeout = SUSPICIOUS_PROFILE_TIMEOUT
        elif profile["state"] == STATE_BLOCKED:
            timeout = BLOCKED_PROFILE_TIMEOUT
        else:
            timeout = OBSERVATION_PROFILE_TIMEOUT
        
        if inactivity < timeout:
            return False
        
        # Check ML history for risk level
        ml_history = profile.get("ml_probability_history", [])
        if ml_history:
            avg_ml_risk = sum(ml_history) / len(ml_history)
        else:
            avg_ml_risk = profile.get("ml_probability", 0.0)
        
        # Risky host with high ML probability -> temporary block
        if avg_ml_risk >= ML_RISK_HIGH_THRESHOLD:
            return "BLOCK"
        
        # Safe host with low ML probability -> delete
        return "DELETE"
    
    # =========================================================================
    # RECALCULATE STATE - DETERMINES OWNER BASED ON TRUST_SCORE
    # CRITICAL: Ownership transfer from ML to TRUST resets trust to 50
    # =========================================================================
    
    def _recalculate_state(self, mac):
        profile = self.host_profiles[mac]
        trust = profile["trust_score"]
        host_age = time.time() - profile["first_seen"]
        packets = profile["packet_count"]
        old_state = profile["state"]
        old_owner = profile.get("owner", "TRUST")
        
        # Determine target state based on trust score
        if trust >= TRUSTED_THRESHOLD:
            target_state = STATE_TRUSTED
        elif trust >= SUSPICIOUS_THRESHOLD:
            target_state = STATE_OBSERVATION
        elif trust >= BLOCKED_THRESHOLD:
            target_state = STATE_SUSPICIOUS
        else:
            target_state = STATE_BLOCKED
        
        # Determine owner based on state and trust
        # Only TRUSTED state can have ML owner
        if target_state == STATE_TRUSTED and host_age > 20 and packets >= MIN_PACKETS_FOR_TRUST:
            new_owner = "ML"
        else:
            new_owner = "TRUST"
        
        # Apply state and owner
        profile["state"] = target_state
        profile["owner"] = new_owner
        
        # Handle transition from ML to TRUST (trust fell below 75)
        # CRITICAL FIX: Reset trust to 50 when leaving ML mode
        if old_owner == "ML" and new_owner == "TRUST":
            profile["trust_score"] = INITIAL_TRUST
            self.logger.warning(
                "OWNERSHIP TRANSFER | mac=%s %s->%s (ML to TRUST) trust RESET to %.2f (was %.2f)",
                mac, old_owner, new_owner, INITIAL_TRUST, trust
            )
        
        # Log state change
        if old_state != profile["state"]:
            self.logger.info(
                "STATE TRANSITION | mac=%s %s->%s trust=%.2f owner=%s",
                mac, old_state, profile["state"], trust, profile["owner"]
            )
        elif old_owner != profile["owner"] and not (old_owner == "ML" and new_owner == "TRUST"):
            self.logger.info(
                "OWNER TRANSITION | mac=%s %s->%s trust=%.2f state=%s",
                mac, old_owner, profile["owner"], trust, profile["state"]
            )
    
    # =========================================================================
    # PRINT PROFILES
    # =========================================================================
    
    def print_profiles(self):
        self.logger.info("=" * 80)
        self.logger.info("HOST TRUST TABLE")
        self.logger.info("=" * 80)
        
        for mac, profile in self.host_profiles.items():
            inactivity = int(time.time() - profile["last_seen"])
            owner = profile.get("owner", "TRUST")
            ml_history = profile.get("ml_probability_history", [])
            if ml_history:
                avg_ml_risk = sum(ml_history) / len(ml_history)
            else:
                avg_ml_risk = profile.get("ml_probability", 0.0)
            
            self.logger.info(
                "%s | state=%s | owner=%s | trust=%.2f | ml=%.4f(avg) | pps=%.2f | inactive=%ss",
                mac, profile["state"], owner, profile["trust_score"], avg_ml_risk,
                profile["packets_per_second"], inactivity
            )
        
        self.logger.info("=" * 80)
    
    # =========================================================================
    # REMOVE SWITCH BLOCK FLAG (called when block expires)
    # =========================================================================
    
    def remove_switch_block_flag(self, mac):
        """Remove the switch_rule_installed flag when block expires"""
        if mac in self.host_profiles:
            profile = self.host_profiles[mac]
            if profile.get("switch_rule_installed", False):
                profile["switch_rule_installed"] = False
                self.logger.info("SWITCH RULE FLAG CLEARED | mac=%s (block expired)", mac)