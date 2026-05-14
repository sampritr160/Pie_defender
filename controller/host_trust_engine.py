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

            "packet_count": 1,

            "successful_replies": 0,

            "failed_requests": 0,

            "flow_refresh_count": 0,

            "unique_destinations": set(),

            "pending_requests": {},

            "last_decay_time": now,

            # =================================================
            # ML FIELDS
            # =================================================

            "ml_probability": 0.0,

            "ml_state": STATE_OBSERVATION,

            "ml_last_check": 0,

            # =================================================
            # BEHAVIOR FEATURES
            # =================================================

            "packets_per_second": 0,

            "bytes_per_second": 0,

            "avg_packet_size": 800,

            "interarrival_mean": 0,

            "interarrival_std": 0,

            "burstiness": 0,

            "destination_growth_rate": 0,

            "destination_entropy": 0,

            "mac_churn_rate": 0,

            "controller_load_impact": 0,

            "syn_ratio": 0.2,

            "icmp_ratio": 0.05,

            "udp_ratio": 0.2
        }

        self.logger.info(
            "PROFILE CREATED | mac=%s trust=%s state=%s",
            mac,
            INITIAL_TRUST,
            STATE_OBSERVATION
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

        elapsed = now - profile["last_seen"]

        profile["packet_count"] += 1

        profile["last_seen"] = now

        profile["unique_destinations"].add(
            dst_mac
        )

        # =================================================
        # PPS
        # =================================================

        if elapsed > 0:

            profile["packets_per_second"] = (
                1 / elapsed
            )

            profile["interarrival_mean"] = (
                elapsed
            )

            profile["interarrival_std"] = (
                elapsed * 0.2
            )

        # =================================================
        # SIMULATED NETWORK METRICS
        # =================================================

        profile["bytes_per_second"] = (
            profile["packets_per_second"] * 800
        )

        profile["avg_packet_size"] = 800

        profile["burstiness"] = min(
            1.0,
            profile["packets_per_second"] / 100
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
            len(profile["unique_destinations"]) / 5
        )

        profile["controller_load_impact"] = (
            profile["packet_count"] * 0.01
        )

        profile["mac_churn_rate"] = (
            len(profile["unique_destinations"]) * 0.1
        )

        return profile

    # =====================================================
    # TRACK REQUEST
    # =====================================================

    def track_request(self, src, dst):

        if src not in self.host_profiles:
            return

        profile = self.host_profiles[src]

        profile["pending_requests"][dst] = (
            time.time()
        )

    # =====================================================
    # VERIFY REPLY
    # =====================================================

    def verify_reply(self, src, dst):

        if dst not in self.host_profiles:
            return False

        profile = self.host_profiles[dst]

        if src not in profile["pending_requests"]:
            return False

        request_time = (
            profile["pending_requests"][src]
        )

        elapsed = (
            time.time() - request_time
        )

        if elapsed <= PENDING_REQUEST_TIMEOUT:

            del profile["pending_requests"][src]

            return True

        return False

    # =====================================================
    # REWARD
    # =====================================================

    def reward_valid_reply(self, mac):

        if mac not in self.host_profiles:
            return

        profile = self.host_profiles[mac]

        profile["successful_replies"] += 1

        replies = (
            profile["successful_replies"]
        )

        failed = (
            profile["failed_requests"]
        )

        total = replies + failed

        ratio = 0

        if total > 0:

            ratio = replies / total

        trust = (
            profile["trust_score"]
        )

        destination_factor = 1.0

        unique_count = len(
            profile["unique_destinations"]
        )

        if unique_count > MAX_NEW_DESTINATIONS:

            overflow = (
                unique_count
                - MAX_NEW_DESTINATIONS
            )

            destination_factor = max(
                0.2,
                1 - (overflow * 0.05)
            )

        # =================================================
        # YOUR ORIGINAL TRUST FORMULA
        # =================================================

        growth = (

            TRUST_LEARNING_RATE

            * ratio

            * destination_factor

            * (1 - (trust / 100))
        )

        age_seconds = (
            time.time()
            - profile["first_seen"]
        )

        age_factor = min(
            1.0,
            age_seconds / 3600
        )

        growth += (
            TRUST_AGING_FACTOR
            * age_factor
        )

        profile["trust_score"] += growth

        profile["trust_score"] = (
            self._clamp_trust(
                profile["trust_score"]
            )
        )

        self._recalculate_state(mac)

    # =====================================================
    # PENALTY
    # =====================================================

    def penalize_failed_request(self, mac):

        if mac not in self.host_profiles:
            return

        profile = self.host_profiles[mac]

        profile["failed_requests"] += 1

        replies = (
            profile["successful_replies"]
        )

        failed = (
            profile["failed_requests"]
        )

        total = replies + failed

        ratio = 0

        if total > 0:

            ratio = replies / total

        penalty = (

            FAILED_REQUEST_PENALTY

            * (1 - ratio)
        )

        profile["trust_score"] -= penalty

        profile["trust_score"] = (
            self._clamp_trust(
                profile["trust_score"]
            )
        )

        self._recalculate_state(mac)

    # =====================================================
    # FLOW REFRESH
    # =====================================================

    def reward_flow_refresh(self, mac):

        if mac not in self.host_profiles:
            return

        profile = self.host_profiles[mac]

        profile["flow_refresh_count"] += 1

    # =====================================================
    # GENERATE ML FEATURE VECTOR
    # =====================================================

    def generate_feature_vector(self, mac):

        if mac not in self.host_profiles:
            return None

        profile = self.host_profiles[mac]

        replies = profile["successful_replies"]

        failed = profile["failed_requests"]

        total = replies + failed

        ratio = 0

        if total > 0:

            ratio = replies / total

        vector = [

            time.time() - profile["first_seen"],

            profile["packet_count"],

            failed,

            ratio,

            len(profile["unique_destinations"]),

            profile["packets_per_second"],

            profile["bytes_per_second"],

            profile["avg_packet_size"],

            profile["interarrival_mean"],

            profile["interarrival_std"],

            profile["burstiness"],

            profile["destination_growth_rate"],

            profile["destination_entropy"],

            profile["flow_refresh_count"],

            profile["mac_churn_rate"],

            profile["controller_load_impact"],

            profile["syn_ratio"],

            profile["icmp_ratio"],

            profile["udp_ratio"],

            math.log1p(profile["packet_count"]),

            math.log1p(profile["bytes_per_second"]),

            math.log1p(profile["flow_refresh_count"]),

            math.log1p(profile["mac_churn_rate"]),

            math.log1p(profile["controller_load_impact"]),

            math.log1p(profile["destination_entropy"])
        ]

        return vector

    # =====================================================
    # APPLY ML RESULT
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
        # ML IMPACT
        # =================================================

        if ml_state == STATE_BLOCKED:

            profile["trust_score"] -= (
                ML_BLOCK_PENALTY
            )

        elif ml_state == STATE_SUSPICIOUS:

            profile["trust_score"] -= (
                ML_SUSPICIOUS_PENALTY
            )

        elif ml_state == STATE_TRUSTED:

            profile["trust_score"] += (
                ML_TRUST_REWARD
            )

        profile["trust_score"] = (
            self._clamp_trust(
                profile["trust_score"]
            )
        )

        self._recalculate_state(mac)

        self.logger.warning(
            "ML ANALYSIS | mac=%s probability=%.4f ml_state=%s trust=%.2f",
            mac,
            probability,
            ml_state,
            profile["trust_score"]
        )

    # =====================================================
    # DECAY
    # =====================================================

    def apply_global_decay(self):

        now = time.time()

        for mac, profile in self.host_profiles.items():

            trust = (
                profile["trust_score"]
            )

            inactivity = (
                now - profile["last_seen"]
            )

            if profile["state"] == STATE_TRUSTED:

                if inactivity > TRUSTED_INACTIVITY_LIMIT:

                    profile["state"] = (
                        STATE_OBSERVATION
                    )

                continue

            if inactivity < 30:
                continue

            elapsed = (
                now - profile["last_decay_time"]
            )

            if elapsed < TRUST_DECAY_INTERVAL:
                continue

            decay = (

                TRUST_DECAY_RATE

                * (inactivity / 60)

                * (1 - (trust / 100))
            )

            profile["trust_score"] -= decay

            profile["trust_score"] = (
                self._clamp_trust(
                    profile["trust_score"]
                )
            )

            profile["last_decay_time"] = now

            self._recalculate_state(mac)

    # =====================================================
    # STATE MACHINE
    # =====================================================

    def _recalculate_state(self, mac):

        profile = self.host_profiles[mac]

        trust = (
            profile["trust_score"]
        )

        replies = (
            profile["successful_replies"]
        )

        failed = (
            profile["failed_requests"]
        )

        total = replies + failed

        ratio = 0

        if total > 0:

            ratio = replies / total

        host_age = (
            time.time()
            - profile["first_seen"]
        )

        if (

            trust >= TRUSTED_THRESHOLD

            and ratio > 0.7

            and host_age > 60
        ):

            profile["state"] = (
                STATE_TRUSTED
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

            self.logger.info(

                "%s | state=%s | trust=%.2f | ml=%.4f | pps=%.2f | dst=%s",

                mac,

                profile["state"],

                profile["trust_score"],

                profile["ml_probability"],

                profile["packets_per_second"],

                len(profile["unique_destinations"])
            )

        self.logger.info("=" * 80)