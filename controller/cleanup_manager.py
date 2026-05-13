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
    # CLEANUP LOOP
    # =====================================================

    def _cleanup_loop(self):

        while True:
            time.sleep(30)
            self.cleanup_profiles()

    # =====================================================
    # PROFILE CLEANUP
    # =====================================================

    def cleanup_profiles(self):

        now = time.time()

        remove_list = []

       