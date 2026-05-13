# =========================================================
# MODULE TOGGLES
# =========================================================

ENABLE_MAC_DETECTOR = 1
ENABLE_TRUST_ENGINE = 1
ENABLE_BEHAVIORAL_ML = 0


# =========================================================
# TRUST STATES
# =========================================================

STATE_OBSERVATION = "OBSERVATION"
STATE_TRUSTED = "TRUSTED"
STATE_SUSPICIOUS = "SUSPICIOUS"
STATE_BLOCKED = "BLOCKED"


# =========================================================
# TRUST THRESHOLDS
# =========================================================

INITIAL_TRUST = 50

TRUSTED_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 40
BLOCKED_THRESHOLD = 15


# =========================================================
# TRUST UPDATE VALUES
# =========================================================

REPLY_REWARD = 3
STABLE_BEHAVIOR_REWARD = 2
FLOW_REFRESH_REWARD = 5

NO_REPLY_PENALTY = -5
ENTROPY_PENALTY = -8
ML_HIGH_RISK_PENALTY = -20


# =========================================================
# FLOW TIMEOUTS
# =========================================================

OBS_IDLE_TIMEOUT = 30
OBS_HARD_TIMEOUT = 90

TRUSTED_IDLE_TIMEOUT = 60
TRUSTED_HARD_TIMEOUT = 180

SUSPICIOUS_IDLE_TIMEOUT = 10
SUSPICIOUS_HARD_TIMEOUT = 20

BLOCK_HARD_TIMEOUT = 120


# =========================================================
# CLEANUP
# =========================================================

OBSERVATION_PROFILE_TIMEOUT = 180
TRUSTED_PROFILE_TIMEOUT = 900
SUSPICIOUS_PROFILE_TIMEOUT = 1200
BLOCKED_PROFILE_TIMEOUT = 300


# =========================================================
# DEMO
# =========================================================

MAC_TABLE_PRINT_INTERVAL = 15
PROFILE_PRINT_INTERVAL = 15