import time
import math

from config import *


class HostTrustEngine:

    def __init__(self, logger):

        self.logger = logger

        self.host_profiles = {}

    # =====================================================
    # PROFILE HELPERS
    # =====================================================

    def profile_exists(self, mac):

        return mac in self.host_profiles

    def get_profile(self, mac):

        return self.host_profiles.get(mac)

    def remove_profile(self, mac):

        if mac in self.host_profiles:

            del self.host_profiles[mac]

            self.logger.warning(
                "PROFILE REMOVED | mac=%s",
                mac
            )

    # =====================================================
    # CLAMP
    # =====================================================

    def _clamp_trust(self, trust):

        if trust > MAX_TRUST_SCORE:
            return MAX_TRUST_SCORE

        if trust < MIN_TRUST_SCORE:
            return MIN_TRUST_SCORE

        return trust

    # =====================================================
    # CREATE PROFILE
    # =====================================================

    def create_profile(self, mac, dpid, port):

        now = time.time()

        self.host_profiles[mac] = {

            "mac": mac,

            "dpid": dpid,

            "port": port,

            "trust_score": INITIAL_TRUST,

            "state": STATE_OBSERVATION,

            "first_seen": now,

            "last_seen": now,

            "packet_count": 0,

            "successful_replies": 0,

            "failed_requests": 0,

            "flow_refresh_count": 0,

            "unique_destinations": set(),

            "last_decay_time": now,

            # =================================================
            # ML
            # =================================================

            "ml_probability": 0.0,

            "ml_state": STATE_OBSERVATION,

            "ml_last_check": 0,

            "under_ml_control": False,

            # =================================================
            # NETWORK FEATURES
            # =================================================

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

            # =================================================
            # INTERNAL
            # =================================================

            "last_packet_time": now,

            "recent_pps": [],

            "inactive_cycles": 0
        }

        self.logger.info(
            "PROFILE CREATED | mac=%s trust=%.2f",
            mac,
            INITIAL_TRUST
        )

        return self.host_profiles[mac]

    # =====================================================
    # UPDATE PROFILE
    # =====================================================

    def update_profile(self, mac, dst_mac):

        if mac not in self.host_profiles:
            return None

        profile = self.host_profiles[mac]

        now = time.time()

        elapsed = (
            now - profile["last_packet_time"]
        )

        if elapsed <= 0:
            elapsed = 0.001

        profile["packet_count"] += 1

        profile["last_seen"] = now

        profile["last_packet_time"] = now

        profile["inactive_cycles"] = 0

        profile["unique_destinations"].add(
            dst_mac
        )

        instant_pps = 1.0 / elapsed

        profile["recent_pps"].append(
            instant_pps
        )

        if len(profile["recent_pps"]) > STATS_WINDOW:

            profile["recent_pps"].pop(0)

        avg_pps = (

            sum(profile["recent_pps"])

            / len(profile["recent_pps"])
        )

        profile["packets_per_second"] = (
            avg_pps
        )

        profile["bytes_per_second"] = (
            avg_pps * 800
        )

        profile["interarrival_mean"] = (
            elapsed
        )

        profile["interarrival_std"] = (
            elapsed * 0.15
        )

        profile["burstiness"] = min(
            1.0,
            avg_pps / HIGH_PPS_THRESHOLD
        )

        profile["destination_growth_rate"] = (

            len(profile["unique_destinations"])

            / max(
                1,
                now - profile["first_seen"]
            )
        )

        profile["destination_entropy"] = min(
            5.0,
            len(profile["unique_destinations"]) / 3
        )

        profile["flow_miss_rate"] = (

            profile["flow_refresh_count"]

            / max(
                1,
                profile["packet_count"]
            )
        )

        profile["controller_load_impact"] = min(
            1.0,
            profile["packet_count"] / 1000
        )

        profile["mac_churn_rate"] = (
            len(profile["unique_destinations"]) * 0.1
        )

        return profile

    # =====================================================
    # TRUST ENGINE REWARD
    # ONLY OBSERVATION HOSTS
    # =====================================================

    def reward_behavior(self, mac):

        if mac not in self.host_profiles:
            return

        profile = self.host_profiles[mac]

        # =================================================
        # TRUST ENGINE DOES NOT CONTROL
        # TRUSTED / ML HOSTS
        # =================================================

        if profile["under_ml_control"]:
            return

        old_trust = profile["trust_score"]

        trust = old_trust

        # =================================================
        # SIMPLE TRUST EQUATION
        # =================================================

        delta_trust = (

            TRUST_LEARNING_RATE

            * (1 - (trust / 100.0))
        )

        if delta_trust < 0.05:

            delta_trust = 0.05

        profile["successful_replies"] += 1

        profile["trust_score"] += delta_trust

        profile["trust_score"] = (
            self._clamp_trust(
                profile["trust_score"]
            )
        )

        self.logger.info(
            "TRUST REWARD | mac=%s delta=%.4f trust=%.2f",
            mac,
            delta_trust,
            profile["trust_score"]
        )

        self._recalculate_state(mac)

    # =====================================================
    # PENALTY
    # ONLY OBSERVATION HOSTS
    # =====================================================

    def penalize_behavior(self, mac):

        if mac not in self.host_profiles:
            return

        profile = self.host_profiles[mac]

        if profile["under_ml_control"]:
            return

        profile["failed_requests"] += 1

        trust = profile["trust_score"]

        penalty = (

            FAILED_REQUEST_PENALTY

            * max(
                0.2,
                trust / 100
            )
        )

        profile["trust_score"] -= penalty

        profile["trust_score"] = (
            self._clamp_trust(
                profile["trust_score"]
            )
        )

        self.logger.warning(
            "TRUST PENALTY | mac=%s penalty=%.2f trust=%.2f",
            mac,
            penalty,
            profile["trust_score"]
        )

        self._recalculate_state(mac)

    # =====================================================
    # FLOW REFRESH
    # =====================================================

    def reward_flow_refresh(self, mac):

        if mac not in self.host_profiles:
            return

        self.host_profiles[mac][
            "flow_refresh_count"
        ] += 1

    # =====================================================
    # ML RESULT
    # ONLY ML MODULE CONTROLS HERE
    # =====================================================

    def apply_ml_result(
        self,
        mac,
        ml_result
    ):

        if mac not in self.host_profiles:
            return

        profile = self.host_profiles[mac]

        probability = (
            ml_result["probability"]
        )

        ml_state = (
            ml_result["state"]
        )

        profile["ml_probability"] = (
            probability
        )

        profile["ml_state"] = (
            ml_state
        )

        profile["ml_last_check"] = (
            time.time()
        )

        # =================================================
        # ML CONTROLS TRUSTED HOST
        # =================================================

        profile["under_ml_control"] = True

        old_trust = profile["trust_score"]

        # =================================================
        # ML TRUST ADJUSTMENT
        # =================================================

        if ml_state == STATE_TRUSTED:

            profile["trust_score"] += (
                ML_TRUST_REWARD
            )

        elif ml_state == STATE_OBSERVATION:

            profile["trust_score"] -= (
                ML_OBSERVATION_PENALTY
            )

        elif ml_state == STATE_SUSPICIOUS:

            profile["trust_score"] -= (
                ML_SUSPICIOUS_PENALTY
            )

        elif ml_state == STATE_BLOCKED:

            profile["trust_score"] -= (
                ML_BLOCK_PENALTY
            )

        profile["trust_score"] = (
            self._clamp_trust(
                profile["trust_score"]
            )
        )

        self.logger.warning(
            "ML TRUST UPDATE | mac=%s old=%.2f new=%.2f ml=%.4f state=%s",
            mac,
            old_trust,
            profile["trust_score"],
            probability,
            ml_state
        )

        # =================================================
        # TRUST DROPPED BELOW TRUSTED
        # RETURN OWNERSHIP TO TRUST ENGINE
        # =================================================

        if profile["trust_score"] < TRUSTED_THRESHOLD:

            profile["state"] = (
                STATE_OBSERVATION
            )

            profile["trust_score"] = (
                INITIAL_TRUST
            )

            profile["under_ml_control"] = False

            self.logger.warning(
                "HOST DOWNGRADED TO OBSERVATION | mac=%s reset_trust=%.2f",
                mac,
                profile["trust_score"]
            )

        else:

            profile["state"] = (
                STATE_TRUSTED
            )

    # =====================================================
    # DECAY
    # ONLY TRUST ENGINE HOSTS
    # =====================================================

    def apply_global_decay(self):

        now = time.time()

        for mac, profile in list(
            self.host_profiles.items()
        ):

            # =================================================
            # ML HOSTS HANDLE THEMSELVES
            # =================================================

            if profile["under_ml_control"]:
                continue

            inactivity = (
                now - profile["last_seen"]
            )

            if inactivity < 30:
                continue

            elapsed = (
                now - profile["last_decay_time"]
            )

            if elapsed < TRUST_DECAY_INTERVAL:
                continue

            profile["inactive_cycles"] += 1

            decay = TRUST_DECAY_RATE

            profile["trust_score"] -= decay

            profile["trust_score"] = (
                self._clamp_trust(
                    profile["trust_score"]
                )
            )

            profile["last_decay_time"] = now

            self.logger.warning(
                "TRUST DECAY | mac=%s decay=%.2f trust=%.2f",
                mac,
                decay,
                profile["trust_score"]
            )

            self._recalculate_state(mac)

    # =====================================================
    # CLEANUP DECISION
    # =====================================================

    def should_cleanup_profile(self, mac):

        if mac not in self.host_profiles:
            return False

        profile = self.host_profiles[mac]

        inactivity = (
            time.time()
            - profile["last_seen"]
        )

        if inactivity < OBSERVATION_PROFILE_TIMEOUT:
            return False

        probability = (
            profile["ml_probability"]
        )

        state = (
            profile["state"]
        )

        # =================================================
        # RISKY HOST
        # =================================================

        if (
            state in [
                STATE_SUSPICIOUS,
                STATE_BLOCKED
            ]
            and probability >= 0.40
        ):

            return "BLOCK"

        # =================================================
        # SAFE OLD HOST
        # =================================================

        if (
            state == STATE_OBSERVATION
            and probability < 0.40
            and profile["trust_score"] <= (
                INITIAL_TRUST - 5
            )
        ):

            return "DELETE"

        return False

    # =====================================================
    # STATE MACHINE
    # =====================================================

    def _recalculate_state(self, mac):

        profile = self.host_profiles[mac]

        # =================================================
        # ML MODULE CURRENTLY OWNS HOST
        # =================================================

        if profile["under_ml_control"]:
            return

        trust = (
            profile["trust_score"]
        )

        host_age = (
            time.time()
            - profile["first_seen"]
        )

        packets = (
            profile["packet_count"]
        )

        # =================================================
        # PROMOTION TO TRUSTED
        # =================================================

        if (

            trust >= TRUSTED_THRESHOLD

            and host_age > 20

            and packets >= MIN_PACKETS_FOR_TRUST
        ):

            profile["state"] = (
                STATE_TRUSTED
            )

            profile["under_ml_control"] = True

            self.logger.info(
                "HOST PROMOTED TO TRUSTED | mac=%s trust=%.2f",
                mac,
                trust
            )

        elif trust >= SUSPICIOUS_THRESHOLD:

            profile["state"] = (
                STATE_OBSERVATION
            )

        elif trust >= BLOCKED_THRESHOLD:

            profile["state"] = (
                STATE_SUSPICIOUS
            )

        else:

            profile["state"] = (
                STATE_BLOCKED
            )

    # =====================================================
    # PRINT
    # =====================================================

    def print_profiles(self):

        self.logger.info("=" * 80)

        self.logger.info(
            "HOST TRUST TABLE"
        )

        self.logger.info("=" * 80)

        for mac, profile in self.host_profiles.items():

            inactivity = int(
                time.time()
                - profile["last_seen"]
            )

            owner = "ML"

            if not profile["under_ml_control"]:

                owner = "TRUST"

            self.logger.info(

                "%s | state=%s | owner=%s | trust=%.2f | ml=%.4f | pps=%.2f | inactive=%ss",

                mac,

                profile["state"],

                owner,

                profile["trust_score"],

                profile["ml_probability"],

                profile["packets_per_second"],

                inactivity
            )

        self.logger.info("=" * 80)