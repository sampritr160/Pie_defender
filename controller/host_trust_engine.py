import time

from config import (
    INITIAL_TRUST,
    TRUSTED_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    BLOCKED_THRESHOLD,
    STATE_OBSERVATION,
    STATE_TRUSTED,
    STATE_SUSPICIOUS,
    STATE_BLOCKED,
    REPLY_REWARD,
    FLOW_REFRESH_REWARD,
    NO_REPLY_PENALTY
)


class HostTrustEngine:

    def __init__(self, logger):
        self.logger = logger

        self.host_profiles = {}

    # =====================================================
    # PROFILE CHECK
    # =====================================================

    def profile_exists(self, mac):
        return mac in self.host_profiles

    def get_profile(self, mac):
        return self.host_profiles.get(mac)

    # =====================================================
    # CREATE PROFILE
    # =====================================================

    def create_profile(self, mac, dpid, port):

        self.host_profiles[mac] = {
            "mac": mac,
            "dpid": dpid,
            "port": port,
            "trust_score": INITIAL_TRUST,
            "state": STATE_OBSERVATION,
            "first_seen": time.time(),
            "last_seen": time.time(),
            "packet_count": 1,
            "reply_count": 0,
            "flow_refresh_count": 0,
            "ml_risk": 0.0
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

    def update_profile(self, mac):

        if mac not in self.host_profiles:
            return None

        profile = self.host_profiles[mac]

        profile["packet_count"] += 1
        profile["last_seen"] = time.time()

        return profile

    # =====================================================
    # REPLY TRACKING
    # =====================================================

    def reward_reply(self, mac):

        if mac not in self.host_profiles:
            return

        profile = self.host_profiles[mac]

        profile["reply_count"] += 1
        profile["trust_score"] += REPLY_REWARD

        self._recalculate_state(mac)

        self.logger.info(
            "TRUST UPDATE | mac=%s reply_reward=%s trust=%s",
            mac,
            REPLY_REWARD,
            profile["trust_score"]
        )

    # =====================================================
    # FLOW REFRESH REWARD
    # =====================================================

    def reward_flow_refresh(self, mac):

        if mac not in self.host_profiles:
            return

        profile = self.host_profiles[mac]

        profile["flow_refresh_count"] += 1
        profile["trust_score"] += FLOW_REFRESH_REWARD

        self._recalculate_state(mac)

        self.logger.info(
            "FLOW REFRESH | mac=%s refresh_count=%s trust=%s",
            mac,
            profile["flow_refresh_count"],
            profile["trust_score"]
        )

    # =====================================================
    # PENALTY
    # =====================================================

    def penalize_no_reply(self, mac):

        if mac not in self.host_profiles:
            return

        profile = self.host_profiles[mac]

        profile["trust_score"] += NO_REPLY_PENALTY

        self._recalculate_state(mac)

        self.logger.warning(
            "TRUST PENALTY | mac=%s trust=%s",
            mac,
            profile["trust_score"]
        )

    # =====================================================
    # STATE RECALCULATION
    # =====================================================

    def _recalculate_state(self, mac):

        profile = self.host_profiles[mac]

        trust = profile["trust_score"]
        old_state = profile["state"]

        if trust >= TRUSTED_THRESHOLD:
            profile["state"] = STATE_TRUSTED

        elif trust >= SUSPICIOUS_THRESHOLD:
            profile["state"] = STATE_OBSERVATION

        elif trust >= BLOCKED_THRESHOLD:
            profile["state"] = STATE_SUSPICIOUS

        else:
            profile["state"] = STATE_BLOCKED

        if old_state != profile["state"]:
            self.logger.warning(
                "STATE CHANGED | mac=%s %s -> %s",
                mac,
                old_state,
                profile["state"]
            )

    # =====================================================
    # FEATURE GENERATION (ML PLACEHOLDER)
    # =====================================================

    def generate_feature_vector(self, mac):

        if mac not in self.host_profiles:
            return None

        profile = self.host_profiles[mac]

        packet_count = profile["packet_count"]
        reply_count = profile["reply_count"]

        reply_ratio = 0.0
        if packet_count > 0:
            reply_ratio = reply_count / packet_count

        host_age = time.time() - profile["first_seen"]

        feature_vector = [
            host_age,
            packet_count,
            reply_ratio,
            profile["flow_refresh_count"],
            profile["trust_score"]
        ]

        self.logger.info(
            "FEATURE VECTOR GENERATED | mac=%s vector=%s",
            mac,
            feature_vector
        )

        return feature_vector

    # =====================================================
    # PROFILE PRINTING
    # =====================================================

    def print_profiles(self):

        self.logger.info("=" * 60)
        self.logger.info("HOST TRUST TABLE")
        self.logger.info("=" * 60)

        for mac, profile in self.host_profiles.items():
            self.logger.info(
                "%s | state=%s | trust=%s | packets=%s | replies=%s | refresh=%s",
                mac,
                profile["state"],
                profile["trust_score"],
                profile["packet_count"],
                profile["reply_count"],
                profile["flow_refresh_count"]
            )

        self.logger.info("TOTAL HOSTS = %s", len(self.host_profiles))
        self.logger.info("=" * 60)