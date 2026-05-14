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

TRUSTED_THRESHOLD = 55

SUSPICIOUS_THRESHOLD = 45

BLOCKED_THRESHOLD = 20


# =========================================================
# LOGISTIC TRUST PARAMETERS
# =========================================================

TRUST_LEARNING_RATE = 4.0

TRUST_AGING_FACTOR = 0.5

FAILED_REQUEST_PENALTY = 7

TRUST_DECAY_RATE = 1

TRUST_DECAY_INTERVAL = 60


# =========================================================
# INACTIVITY
# =========================================================

TRUSTED_INACTIVITY_LIMIT = 300

OBSERVATION_INACTIVITY_LIMIT = 120


# =========================================================
# REQUEST TRACKING
# =========================================================

PENDING_REQUEST_TIMEOUT = 10


# =========================================================
# COMMUNICATION PARAMETERS
# =========================================================

MIN_REPLY_RATIO = 0.60

MAX_NEW_DESTINATIONS = 10

HIGH_PPS_THRESHOLD = 80

MIN_STABLE_REPLIES = 10


# =========================================================
# ML ENGINE
# =========================================================

ML_RECHECK_INTERVAL = 15

ML_BLOCK_THRESHOLD = 0.90

ML_SUSPICIOUS_THRESHOLD = 0.75

ML_OBSERVATION_THRESHOLD = 0.40

ML_TRUST_REWARD = 5

ML_SUSPICIOUS_PENALTY = 10

ML_BLOCK_PENALTY = 25


# =========================================================
# FLOW TIMEOUTS
# =========================================================

OBS_IDLE_TIMEOUT = 5

OBS_HARD_TIMEOUT = 10

TRUSTED_IDLE_TIMEOUT = 60

TRUSTED_HARD_TIMEOUT = 0

SUSPICIOUS_IDLE_TIMEOUT = 5

SUSPICIOUS_HARD_TIMEOUT = 10

BLOCK_HARD_TIMEOUT = 300


# =========================================================
# CLEANUP
# =========================================================

OBSERVATION_PROFILE_TIMEOUT = 180

TRUSTED_PROFILE_TIMEOUT = 900

SUSPICIOUS_PROFILE_TIMEOUT = 1200

BLOCKED_PROFILE_TIMEOUT = 300


# =========================================================
# STATUS / DEBUG
# =========================================================

MAC_TABLE_PRINT_INTERVAL = 15

PROFILE_PRINT_INTERVAL = 15