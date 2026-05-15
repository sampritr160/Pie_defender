# =========================================================
# MODULE TOGGLES
# =========================================================

ENABLE_MAC_DETECTOR = 0

ENABLE_TRUST_ENGINE = 1

ENABLE_BEHAVIORAL_ML = 1


# =========================================================
# TRUST STATES
# =========================================================

STATE_OBSERVATION = "OBSERVATION"

STATE_TRUSTED = "TRUSTED"

STATE_SUSPICIOUS = "SUSPICIOUS"

STATE_BLOCKED = "BLOCKED"


# =========================================================
# TRUST SCORE LIMITS
# =========================================================

MIN_TRUST_SCORE = 0

MAX_TRUST_SCORE = 100


# =========================================================
# INITIAL TRUST
# =========================================================

INITIAL_TRUST = 50


# =========================================================
# TRUST THRESHOLDS
# =========================================================
#
# OBSERVATION:
# Default state for all new hosts
#
# TRUSTED:
# Stable + active hosts
#
# SUSPICIOUS:
# Low trust or risky ML history
#
# BLOCKED:
# Dangerous behavior
#
# =========================================================

TRUSTED_THRESHOLD = 75

SUSPICIOUS_THRESHOLD = 45

BLOCKED_THRESHOLD = 20


# =========================================================
# TRUST ENGINE PARAMETERS
# =========================================================
#
# SIMPLE TRUST ENGINE:
#
# ΔT = α × (1 - T/100)
#
# ONLY ACTIVE INSIDE
# TRUST ENGINE MODULE
#
# =========================================================

TRUST_LEARNING_RATE = 1.5

FAILED_REQUEST_PENALTY = 6

TRUST_DECAY_RATE = 2.0

TRUST_DECAY_INTERVAL = 30


# =========================================================
# INACTIVITY
# =========================================================
#
# TRUSTED HOST:
# If inactive too long:
#
# -> reset to OBSERVATION
# -> trust reset to 50
# -> ML stops controlling
# -> Trust Engine takes over again
#
# =========================================================

TRUSTED_INACTIVITY_LIMIT = 45

OBSERVATION_INACTIVITY_LIMIT = 90


# =========================================================
# STABLE METRIC WINDOWS
# =========================================================

STATS_WINDOW = 10

MIN_PACKETS_FOR_TRUST = 10

HIGH_PPS_THRESHOLD = 300


# =========================================================
# ML ENGINE
# =========================================================
#
# ML ONLY HANDLES:
#
# TRUSTED HOSTS
#
# ML modifies trust score
# while host stays TRUSTED
#
# If trust drops below threshold:
#
# -> reset to OBSERVATION
# -> trust reset to 50
# -> Trust Engine controls again
#
# =========================================================

ML_RECHECK_INTERVAL = 10

ML_BLOCK_THRESHOLD = 0.95

ML_SUSPICIOUS_THRESHOLD = 0.80

ML_OBSERVATION_THRESHOLD = 0.40

ML_TRUST_REWARD = 3

ML_SUSPICIOUS_PENALTY = 8

ML_BLOCK_PENALTY = 20


# =========================================================
# FLOW TIMEOUTS
# =========================================================
#
# OBSERVATION:
# Short-medium flows
#
# TRUSTED:
# Long-term stable flows
#
# SUSPICIOUS:
# Very short flows
#
# =========================================================

OBS_IDLE_TIMEOUT = 10

OBS_HARD_TIMEOUT = 25

TRUSTED_IDLE_TIMEOUT = 60

TRUSTED_HARD_TIMEOUT = 0

SUSPICIOUS_IDLE_TIMEOUT = 5

SUSPICIOUS_HARD_TIMEOUT = 10

BLOCK_HARD_TIMEOUT = 300


# =========================================================
# CLEANUP
# =========================================================
#
# OBSERVATION:
# Safe inactive hosts removed
#
# TRUSTED:
# First reset to OBSERVATION
#
# SUSPICIOUS:
# Kept longer for analysis
#
# BLOCKED:
# Temporary block rule
#
# =========================================================

OBSERVATION_PROFILE_TIMEOUT = 180

TRUSTED_PROFILE_TIMEOUT = 300

SUSPICIOUS_PROFILE_TIMEOUT = 600

BLOCKED_PROFILE_TIMEOUT = 300


# =========================================================
# STATUS / DEBUG
# =========================================================

MAC_TABLE_PRINT_INTERVAL = 15

PROFILE_PRINT_INTERVAL = 15