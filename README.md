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

## 👤 Author

**Samprit**
