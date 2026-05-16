# Pie Defender

**Pie Defender** is an SDN-based network security project using the Ryu controller and machine learning techniques to detect and mitigate network attacks (e.g., DoS, MAC spoofing). 

This repository contains:
- SDN controller logic
- Attack simulation scripts
- Machine learning models
- Supporting scripts and configuration files

---

## 📁 Project Structure

```
attack/         → Attack scripts (DoS, fake host, MAC spoofing)
controller/     → Ryu controller implementations
ml/             → ML models, scalers, and training artifacts
scripts/        → Helper and automation scripts
logs/           → Runtime logs (ignored by git)
requirements.txt
```

---

## ⚙️ Prerequisites

- Python 3.8 or higher
- Git
- Linux/macOS (recommended for Ryu)

---

## 🚀 Clone and Setup Instructions

Follow these steps on **any new machine**.

### 1. Clone the repository

```bash
git clone https://github.com/Samprit74/Pie-defender.git
cd Pie-defender
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
```

### 3. Activate the virtual environment

```bash
source venv/bin/activate
```

You should see `(venv)` in your terminal prompt.

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

This installs all required Python libraries, including Ryu and ML dependencies.

---

## 🎯 Running the Project

**Example (Ryu controller):**

```bash
ryu-manager controller/piedefender_controller2.py
```

Attack scripts can be executed from the `attack/` directory depending on the experiment setup.

---

## 💡 Notes

- The `venv/` directory is intentionally not tracked by Git.
- Always activate the virtual environment before running the project.
- If dependencies change, regenerate `requirements.txt` using:

```bash
pip freeze > requirements.txt
```

---

## 🖥️ How to Run the Project (Three-Terminal Workflow)

This project is executed using **three separate terminals**, each with a specific role. They must be run in the correct order.

---

### 🟢 Terminal 1 — Start the Ryu Controller (Pie Defender)

**Purpose:**
- Runs the SDN controller
- Handles MAC learning, attack detection, and mitigation
- Logs PACKET_IN events and blocking decisions

**Command:**

```bash
source venv/bin/activate
ryu-manager controller/piedefender_controller2.py
```

**Expected output:**
- Switch connection messages (`SWITCH CONNECTED dpid=X`)
- MAC table updates
- Attack detection logs (e.g., `MAC injection blocked`)

> ⚠️ **This terminal must remain running at all times.**

---

### 🟡 Terminal 2 — Start Mininet Topology and Open Host Terminals

**Purpose:**
- Creates the SDN topology
- Connects switches to the remote Ryu controller
- Opens host terminals for traffic generation and attack simulation

#### Step 1 — Start Mininet:

```bash
sudo mn --topo tree,depth=2,fanout=2 \
        --controller=remote,ip=127.0.0.1,port=6653 \
        --switch ovs,protocols=OpenFlow13 \
        --ipbase=10.0.0.0/8
```

This creates:
- 3 switches (`s1`, `s2`, `s3`)
- 4 hosts (`h1`, `h2`, `h3`, `h4`)
- OpenFlow 1.3 connections to the Ryu controller

#### Step 2 — Open host terminals inside Mininet CLI:

At the `mininet>` prompt, run:

```bash
xterm h1 h2
```

**Purpose:**
- Opens terminal windows for host `h1` and `h2`
- Used to generate traffic or simulate attacks

**Example:**
- Normal traffic (ping tests)
- MAC spoofing
- DoS simulation

You can also open other hosts:

```bash
xterm h3 h4
```

**Exit Mininet when finished:**

```bash
exit
```

---

### 🔵 Terminal 3 — Monitor OpenFlow Rules (Optional but Recommended)

**Purpose:**
- Observes flow rules installed by the controller
- Verifies mitigation actions (drop rules, flood rules, etc.)
- Useful for debugging and experiments

**Command:**

```bash
watch -n 1 "sudo ovs-ofctl dump-flows s1 -O OpenFlow13"
```

**Notes:**
- Replace `s1` with `s2` or `s3` to inspect other switches
- This terminal is read-only (monitoring only)

---

## 📋 Execution Order Summary

| Step | Terminal | Command |
|------|----------|---------|
| 1️⃣ | Terminal 1 | Start Ryu controller |
| 2️⃣ | Terminal 2 | Start Mininet topology |
| 3️⃣ | Terminal 3 | Monitor flow rules (optional) |

> ⚠️ **The controller must always be started before Mininet.**

---

## ❓ Why This Matters

The `xterm` step is important because:
- It enables traffic generation from hosts
- It is required for attack simulation
- It allows controlled experimentation
- It demonstrates real-time controller reaction

Without documenting it clearly, someone cloning the repo would not know how to trigger traffic.

---




Now new feature introduced . we try to make a temporal flow install and  stat check system

## Repository Structure

```
Pie-defender/
├── attack/                         → Attack simulation scripts
├── controller/                     → Ryu controller implementation
│   ├── piedefender_controller3.py  → Main controller (Version 2)
│   ├── host_trust_engine.py        → Trust Engine module
│   ├── behavioral_ml_engine.py     → ML Engine module
│   ├── cleanup_manager.py          → Periodic cleanup and blocking
│   └── config.py                   → All thresholds and parameters
├── ml/current/                     → Active ML model files
├── scripts/                        → Helper automation scripts
├── logs/                           → Runtime logs (git ignored)
└── requirements.txt                → Python dependencies
```

---

## Prerequisites

- Python 3.8 or higher
- Git
- Linux / macOS (recommended for Ryu)
- Open vSwitch (OVS)
- Mininet

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Samprit74/Pie-defender.git
cd Pie-defender
```

### 2. Create and Activate Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Place ML Model Files

```bash
cp piedefender_model.pkl ml/current/
cp piedefender_features.pkl ml/current/
cp piedefender_scaler.pkl ml/current/
cp piedefender_trust_config.pkl ml/current/
cp piedefender_metrics.pkl ml/current/
```

---

## Running the Project (Three-Terminal Workflow)

### Terminal 1 — Start the Ryu Controller

```bash
source venv/bin/activate
ryu-manager controller/piedefender_controller3.py
```

### Terminal 2 — Start Mininet Topology

```bash
sudo mn --topo linear,3 \
        --controller=remote,ip=127.0.0.1,port=6653 \
        --switch ovs,protocols=OpenFlow13 \
        --ipbase=10.0.0.0/8
```

Open host terminals:

```bash
mininet> xterm h1 h2 h3
```

Generate normal traffic:

```bash
# In h1 xterm
ping 10.0.0.3

# In h2 xterm
ping 10.0.0.3
```

Run attack simulation:

```bash
# In h3 xterm
python3 attack/stage1_fake_host_attack2.py
```

Exit Mininet:

```bash
mininet> exit
```

### Terminal 3 — Monitor OpenFlow Rules (Optional)

```bash
watch -n 1 "sudo ovs-ofctl dump-flows s1 -O OpenFlow13"
```

---

## Execution Order

| Step | Terminal | Command |
|:----:|:--------:|---------|
| 1 | Terminal 1 | Start Ryu controller |
| 2 | Terminal 2 | Start Mininet topology |
| 3 | Terminal 3 | Monitor flow rules (optional) |

> **Note:** The controller must be started before Mininet.

---

## Architecture Overview

The system separates host management into two distinct phases with strict ownership separation.

```
                    NEW HOST
                        │
                        ▼
              ┌─────────────────┐
              │   OBSERVATION   │
              │   owner=TRUST   │
              │   trust=50      │
              └─────────────────┘
                        │
                        │ trust >= 75
                        ▼
              ┌─────────────────┐
              │  TRUSTED (1st)  │
              │   owner=ML      │
              │   bootstrap     │
              └─────────────────┘
                        │
                        │ flow expires (30 sec)
                        ▼
              ┌─────────────────┐
              │  TRUSTED (2nd+) │
              │   owner=ML      │
              │   ML runs       │
              └─────────────────┘
                        │
            ┌───────────┴───────────┐
            │                       │
      trust >= 75               trust < 75
            │                       │
            ▼                       ▼
    stay TRUSTED            downgrade to OBSERVATION
    install new flow        trust RESET to 50
    repeat every 30 sec     owner=TRUST
```

---

## Core Components

| Component | Responsibility |
|-----------|----------------|
| **Trust Engine** | Controls OBSERVATION hosts using simple trust formula |
| **ML Engine** | Controls TRUSTED hosts using XGBoost model |
| **Cleanup Manager** | Deletes safe profiles or blocks risky inactive hosts |
| **Controller** | Routes packets and calls appropriate engine based on owner |

---

## Trust Formulas

### Phase 1: OBSERVATION (Trust Engine)

```
ΔT = TRUST_LEARNING_RATE × (1 - T/100)

where:
- TRUST_LEARNING_RATE = 1.5
- T = current trust score
```

| Current Trust | Delta | New Trust |
|:-------------:|:-----:|:---------:|
| 50 | 0.75 | 50.75 |
| 70 | 0.45 | 70.45 |
| 90 | 0.15 | 90.15 |

### Phase 2: TRUSTED (ML Engine)

```
ΔT = ml_adjustment - decay

where:
- ml_adjustment based on probability
- decay = 2.0 (every 30 seconds, always applies)
```

### ML Probability to Trust Adjustment

| Probability Range | Action | Formula |
|:-----------------:|:------:|---------|
| < 0.50 | INCREASE | +1.2 × (1 - p) |
| 0.50 - 0.70 | NEUTRAL | 0 |
| > 0.70 | DECREASE | -5.0 × (p - 0.7) |

### Decay (Applies to ALL hosts)

```
Every 30 seconds:
    trust_score = trust_score - 2.0

Exception: No decay when trust is in protected range (73-78)
```

---

## State Transitions

| Trust Score | State | Owner |
|:-----------:|:-----:|:-----:|
| ≥ 75 | TRUSTED | ML |
| 45 – 74 | OBSERVATION | TRUST |
| 20 – 44 | SUSPICIOUS | TRUST |
| < 20 | BLOCKED | TRUST |

---

## The Problems It Solves

| Problem | Description | Solution |
|:--------|:------------|:---------|
| **Slow Stealth Attacks** | Attacks that gradually ramp up over hours/days bypass threshold-based detection | ML tracks behavioral trends over time (reply_ratio decreasing, entropy increasing) |
| **Black Friday False Positives** | High-traffic legitimate events are misidentified as attacks | ML uses 11 features, not just PPS; distinguishes flash crowds from attacks |
| **Permanent Trust Blindness** | Trusted hosts get permanent flows, controller loses visibility | Trusted flows expire every 30 seconds, ensuring periodic visibility |
| **Trust Oscillation** | Hosts bounce between TRUSTED and OBSERVATION | Decay protection range (73-78) prevents oscillation |

---

## ML Model Features (11 features)

| Feature | Source | What It Measures |
|:--------|:------:|:-----------------|
| host_age | Profile | How long host has been known |
| reply_ratio | Profile | Success rate of requests |
| unique_destinations | Profile | Total destinations contacted |
| destination_growth_rate | Calculated | New destinations per second |
| destination_entropy | Calculated | Randomness of destination pattern |
| ml_probability_trend | History | Slope of last 5 ML probabilities |
| is_new_destination | Current packet | 1 if destination never seen before |
| time_since_last_seen | Current packet | Seconds since last packet |
| syn_ratio | Profile | TCP SYN packet proportion |
| icmp_ratio | Profile | ICMP packet proportion |
| udp_ratio | Profile | UDP packet proportion |

---

## Attack Types Detected

| Attack Type | Detection Method |
|:------------|:-----------------|
| Fake Host Registration | Low reply_ratio, high is_new_destination |
| Port Scanning | High unique_destinations, high destination_growth_rate |
| SYN Flood | High syn_ratio, low reply_ratio |
| Compromised Trusted Host | ML probability trend increasing over time |
| Slow Stealth Attack | Destination_entropy gradually increasing, reply_ratio gradually decreasing |

---

## Key Design Rules

| Rule | Description |
|:----:|:------------|
| 1 | State always follows trust_score. No external forced state changes. |
| 2 | Decay applies to ALL hosts every 30 seconds, regardless of activity. |
| 3 | Decay is skipped when trust is in protected range (73-78) to prevent oscillation. |
| 4 | When trust falls below 75 in ML mode, trust is RESET to 50 and ownership returns to Trust Engine. |
| 5 | ML only adjusts trust_score. State changes are handled by Trust Engine. |
| 6 | ml_probability_history is preserved for cleanup decisions. |

---

## ML Model Performance

| Metric | Value |
|:------:|:-----:|
| Accuracy | 98.6% |
| Precision | 97.6% |
| Recall | 99.1% |
| F1-Score | 98.3% |
| ROC-AUC | 99.9% |

### Top Feature Importance

| Feature | Importance |
|:--------|:----------:|
| reply_ratio | 38% |
| is_new_destination | 22% |
| host_age | 10% |
| time_since_last_seen | 8% |
| destination_entropy | 6% |

---

## Troubleshooting

| Issue | Solution |
|:------|:---------|
| Module not found | Activate virtual environment: `source venv/bin/activate` |
| Ryu connection failed | Ensure controller is started BEFORE Mininet |
| ML model not loading | Verify files exist in `ml/current/` |
| No packet_in logs | Check OpenFlow version (1.3 required) |
| Blocked host still communicating | Check flow rules with Terminal 3 |

---

## Author

**Samprit**

---

## License

This project is for research and educational purposes.
```

This is the complete markup code. Copy and paste it directly into your `README.md` file. It includes all diagrams, formulas, tables, and code blocks with proper formatting.

## 👤 Author

**Samprit**
