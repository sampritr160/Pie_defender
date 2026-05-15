import time
import threading

from config import (
    OBSERVATION_PROFILE_TIMEOUT,
    TRUSTED_PROFILE_TIMEOUT,
    SUSPICIOUS_PROFILE_TIMEOUT,
    BLOCKED_PROFILE_TIMEOUT,
    BLOCK_HARD_TIMEOUT,
    STATE_OBSERVATION,
    STATE_TRUSTED,
    STATE_SUSPICIOUS,
    STATE_BLOCKED
)


class CleanupManager:

    def __init__(
        self,
        logger,
        trust_engine,
        mitigator=None,
        datapaths=None
    ):

        self.logger = logger

        self.trust_engine = trust_engine

        self.mitigator = mitigator

        self.datapaths = datapaths

        threading.Thread(

            target=self._cleanup_loop,

            daemon=True

        ).start()

    # =====================================================
    # LOOP
    # =====================================================

    def _cleanup_loop(self):

        while True:

            time.sleep(30)

            try:

                self.cleanup_profiles()

            except Exception as e:

                self.logger.error(
                    "CLEANUP LOOP FAILED | %s",
                    e
                )

    # =====================================================
    # GET TIMEOUT
    # =====================================================

    def _get_timeout(self, state):

        if state == STATE_OBSERVATION:

            return OBSERVATION_PROFILE_TIMEOUT

        elif state == STATE_TRUSTED:

            return TRUSTED_PROFILE_TIMEOUT

        elif state == STATE_SUSPICIOUS:

            return SUSPICIOUS_PROFILE_TIMEOUT

        elif state == STATE_BLOCKED:

            return BLOCKED_PROFILE_TIMEOUT

        return OBSERVATION_PROFILE_TIMEOUT

    # =====================================================
    # TEMPORARY BLOCK
    # =====================================================

    def _block_host(self, mac):

        if self.mitigator is None:
            return

        if self.datapaths is None:
            return

        for datapath in self.datapaths.values():

            try:

                self.mitigator.install_mac_drop_rule(

                    datapath,

                    mac,

                    hard_timeout=BLOCK_HARD_TIMEOUT
                )

                self.logger.warning(

                    "TEMPORARY BLOCK INSTALLED | mac=%s timeout=%ss",

                    mac,

                    BLOCK_HARD_TIMEOUT
                )

            except Exception as e:

                self.logger.error(

                    "BLOCK INSTALL FAILED | mac=%s error=%s",

                    mac,

                    e
                )

    # =====================================================
    # CLEANUP
    # =====================================================

    def cleanup_profiles(self):

        now = time.time()

        remove_list = []

        for mac, profile in list(
            self.trust_engine.host_profiles.items()
        ):

            try:

                last_seen = profile.get(
                    "last_seen",
                    now
                )

                elapsed = (
                    now - last_seen
                )

                state = profile.get(
                    "state",
                    STATE_OBSERVATION
                )

                timeout = self._get_timeout(
                    state
                )

                # =========================================
                # STILL ACTIVE
                # =========================================

                if elapsed < timeout:

                    continue

                probability = profile.get(
                    "ml_probability",
                    0.0
                )

                trust = profile.get(
                    "trust_score",
                    0.0
                )

                # =========================================
                # TRUSTED HOST INACTIVE
                # RESET TO OBSERVATION
                # =========================================

                if state == STATE_TRUSTED:

                    profile["state"] = (
                        STATE_OBSERVATION
                    )

                    profile["trust_score"] = 50

                    self.logger.warning(

                        "TRUSTED HOST RESET | mac=%s trust=50.00",

                        mac
                    )

                    continue

                # =========================================
                # FINAL DECISION
                # =========================================

                decision = (
                    self.trust_engine.should_cleanup_profile(
                        mac
                    )
                )

                # =========================================
                # SAFE OLD HOST
                # DELETE
                # =========================================

                if decision == "DELETE":

                    remove_list.append(mac)

                    self.logger.warning(

                        "SAFE PROFILE EXPIRED | mac=%s state=%s trust=%.2f inactivity=%ss",

                        mac,

                        state,

                        trust,

                        int(elapsed)
                    )

                # =========================================
                # RISKY HOST
                # TEMPORARY BLOCK
                # =========================================

                elif decision == "BLOCK":

                    self.logger.warning(

                        "RISKY PROFILE DETECTED | mac=%s state=%s ml=%.4f inactivity=%ss",

                        mac,

                        state,

                        probability,

                        int(elapsed)
                    )

                    self._block_host(mac)

                # =========================================
                # KEEP PROFILE
                # =========================================

                else:

                    self.logger.info(

                        "PROFILE RETAINED | mac=%s state=%s trust=%.2f ml=%.4f",

                        mac,

                        profile.get(
                            "state"
                        ),

                        trust,

                        probability
                    )

            except Exception as e:

                self.logger.error(
                    "PROFILE CLEANUP CHECK FAILED | mac=%s error=%s",
                    mac,
                    e
                )

        # =================================================
        # REMOVE SAFE PROFILES
        # =================================================

        for mac in remove_list:

            try:

                self.trust_engine.remove_profile(
                    mac
                )

                self.logger.warning(
                    "PROFILE CLEANED | mac=%s",
                    mac
                )

            except Exception as e:

                self.logger.error(
                    "PROFILE DELETE FAILED | mac=%s error=%s",
                    mac,
                    e
                )