import time
import threading

from config import (
    OBSERVATION_PROFILE_TIMEOUT,
    TRUSTED_PROFILE_TIMEOUT,
    SUSPICIOUS_PROFILE_TIMEOUT,
    BLOCKED_PROFILE_TIMEOUT,
    STATE_OBSERVATION,
    STATE_TRUSTED,
    STATE_SUSPICIOUS,
    STATE_BLOCKED
)


class CleanupManager:

    def __init__(self, logger, trust_engine):

        self.logger = logger

        self.trust_engine = trust_engine

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

            self.cleanup_profiles()

    # =====================================================
    # CLEANUP
    # =====================================================

    def cleanup_profiles(self):

        now = time.time()

        remove_list = []

        for mac, profile in self.trust_engine.host_profiles.items():

            last_seen = profile["last_seen"]

            elapsed = now - last_seen

            state = profile["state"]

            timeout = None

            if state == STATE_OBSERVATION:

                timeout = (
                    OBSERVATION_PROFILE_TIMEOUT
                )

            elif state == STATE_TRUSTED:

                timeout = (
                    TRUSTED_PROFILE_TIMEOUT
                )

            elif state == STATE_SUSPICIOUS:

                timeout = (
                    SUSPICIOUS_PROFILE_TIMEOUT
                )

            elif state == STATE_BLOCKED:

                timeout = (
                    BLOCKED_PROFILE_TIMEOUT
                )

            if elapsed >= timeout:

                remove_list.append(mac)

        for mac in remove_list:

            del self.trust_engine.host_profiles[mac]

            self.logger.warning(
                "PROFILE CLEANED | mac=%s",
                mac
            )