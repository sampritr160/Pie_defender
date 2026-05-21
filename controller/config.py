# =============================================================================
# PIEDEFENDER v2 CONFIGURATION FILE
# All thresholds, timeouts, and parameters for the SDN security framework
# =============================================================================

# =============================================================================
# MODULE TOGGLES
# =============================================================================
ENABLE_MAC_DETECTOR = 0
ENABLE_TRUST_ENGINE = 1
ENABLE_BEHAVIORAL_ML = 1

# =============================================================================
# TRUST STATES
# =============================================================================
STATE_OBSERVATION = "OBSERVATION"
STATE_TRUSTED = "TRUSTED"
STATE_SUSPICIOUS = "SUSPICIOUS"
STATE_BLOCKED = "BLOCKED"

# =============================================================================
# TRUST SCORE LIMITS
# =============================================================================
MIN_TRUST_SCORE = 0
MAX_TRUST_SCORE = 100
INITIAL_TRUST = 50

# =============================================================================
# TRUST THRESHOLDS
# =============================================================================
TRUSTED_THRESHOLD = 75
SUSPICIOUS_THRESHOLD = 45
BLOCKED_THRESHOLD = 20

# =============================================================================
# TRUST ENGINE PARAMETERS (OBSERVATION STATE ONLY)
# Formula: delta_trust = TRUST_LEARNING_RATE * (1 - trust_score/100)
# Minimum reward of 0.1 prevents trust from freezing at 100
# =============================================================================
TRUST_LEARNING_RATE = 1.5
FAILED_REQUEST_PENALTY = 6
TRUST_DECAY_RATE = 2.0
TRUST_DECAY_INTERVAL = 30
MIN_TRUST_REWARD = 0.1

# =============================================================================
# DECAY PROTECTION RANGE (trust between these values will NOT decay)
# Prevents oscillation between TRUSTED and OBSERVATION
# =============================================================================
DECAY_PROTECTION_LOWER = 73
DECAY_PROTECTION_UPPER = 78

# =============================================================================
# INACTIVITY HANDLING
# =============================================================================
TRUSTED_INACTIVITY_LIMIT = 45
OBSERVATION_INACTIVITY_LIMIT = 90

# =============================================================================
# STABLE METRIC WINDOWS
# =============================================================================
STATS_WINDOW = 10
MIN_PACKETS_FOR_TRUST = 10
HIGH_PPS_THRESHOLD = 300

# =============================================================================
# ML ENGINE PARAMETERS
# =============================================================================
ML_RECHECK_INTERVAL = 10
ML_TRUST_INCREASE_THRESHOLD = 0.50
ML_TRUST_DECREASE_THRESHOLD = 0.70
ML_TRUST_INCREASE_REWARD = 1.2
ML_TRUST_DECREASE_PENALTY = 5.0

# =============================================================================
# FLOW TIMEOUTS (seconds)
# =============================================================================
OBS_IDLE_TIMEOUT = 10
OBS_HARD_TIMEOUT = 25

TRUSTED_IDLE_TIMEOUT = 60
TRUSTED_HARD_TIMEOUT = 30

SUSPICIOUS_IDLE_TIMEOUT = 5
SUSPICIOUS_HARD_TIMEOUT = 10

BLOCK_HARD_TIMEOUT = 300

# =============================================================================
# CLEANUP TIMEOUTS (seconds)
# =============================================================================
OBSERVATION_PROFILE_TIMEOUT = 180
TRUSTED_PROFILE_TIMEOUT = 300
SUSPICIOUS_PROFILE_TIMEOUT = 600
BLOCKED_PROFILE_TIMEOUT = 300

# =============================================================================
# ML RISK THRESHOLDS (for cleanup decisions)
# =============================================================================
ML_RISK_HIGH_THRESHOLD = 0.50
ML_RISK_VERY_HIGH_THRESHOLD = 0.75

# =============================================================================
# ENTROPY THRESHOLD FOR ML=0.00 HOSTS (never reached TRUSTED state)
# Higher entropy = more destinations = wider scanning behavior
# Range: 0.0 (single destination) to ~5.0 (many random destinations)
# =============================================================================
ENTROPY_BLOCK_THRESHOLD = 3.1

# =============================================================================
# TEMPORARY BLOCK DURATION (seconds)
# =============================================================================
TEMPORARY_BLOCK_DURATION = 300

# =============================================================================
# STATUS / DEBUG
# =============================================================================
MAC_TABLE_PRINT_INTERVAL = 15
PROFILE_PRINT_INTERVAL = 15  

# =============================================================================
# SWITCH SIDE BLOCK DURATION (seconds)
# =============================================================================
SWITCH_SIDE_BLOCK_DURATION = 300  # 5 minutes in seconds
