**✅ HERE IS THE FULL COMPLETE README.md**  
Just copy everything **inside the code block** below and paste it directly into your `README.md` file.

```markdown
# PIEDEFENDER v2
**Adaptive SDN Security Framework for MAC Injection and DoS Detection**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Ryu](https://img.shields.io/badge/SDN-Ryu_Controller-green)
![OpenFlow](https://img.shields.io/badge/OpenFlow-1.3-orange)
![Mininet](https://img.shields.io/badge/Emulator-Mininet-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📋 Project Overview

**PIEDEFENDER v2** is a modular, real-time SDN security framework built on the **Ryu SDN Controller**. It detects and mitigates **MAC Injection attacks** and **DoS/Packet-In flooding attacks** using behavioral analysis, advanced port-status verification, and Machine Learning.

### Key Problems Solved
- MAC table pollution via spoofed Packet-In messages
- Packet-In flooding attacks on the controller
- Stealthy reconnaissance attacks
- Untrusted dynamic MAC learning in SDN

**PIEDEFENDER v2** provides trust-aware MAC learning, port-status verification (PDF Algorithm 2), and SVM-based DoS detection with automatic switch-level mitigation.

---

## ✨ Key Features

- Real-time MAC Injection Detection with graduated response
- Advanced **Port-Status Verification Algorithm**
- Dynamic Edge vs Internal port classification
- 5-Feature SVM-based DoS Detection
- Proactive OpenFlow drop rule mitigation
- Real-time logging and MAC table monitoring
- Fully modular architecture

---

## 🏗️ System Architecture

- **Controller Layer** (`controller2.py`) — Main Ryu application
- **MAC Injection Detection** (`mac_injection_module2.py`)
- **DoS Detection** (`dos_detection2.py`)
- **Mitigation Engine** (`mitigation2.py`)

**ML Model**: SVM with StandardScaler (5 behavioral features)

---

## 📁 Project Directory Structure

```bash
piedefender-v2/
├── controller/
│   ├── controller2.py
│   ├── mac_injection_module2.py
│   ├── dos_detection2.py
│   └── mitigation2.py
├── ml/
│   ├── piedefender_svm_model2.pkl
│   └── piedefender_scaler2.pkl
├── attack/
│   ├── mac_injection_attack.py
│   ├── dos_attack.py
│   └── stealth_attack.py
├── topology/
├── logs/
├── requirements.txt
├── README.md
└── run_controller.sh
```

---

## 📘 Module Documentation

### 1. controller2.py
Main Ryu application. Controls detection mode via `PIEDEFENDER_MODE` (1 = MAC only, 2 = DoS only, 3 = Both).

**Important Handlers:**
- `switch_features_handler()` — Installs default Packet-In rule
- `port_status_handler()` — Triggers verification mode
- `packet_in_handler()` — Core logic for detection and mitigation

### 2. mac_injection_module2.py
Implements **PDF Algorithm 2** with port-status verification.

**Core Functions:**
- `notify_port_status()` — Puts port into verification mode
- `process_packet()` — MAC learning, verification, and injection detection
- Uses temporary buffer during verification to prevent false MAC updates

### 3. dos_detection2.py
Extracts 5 features using sliding window:
- **RPI** – Rate of Packet-In
- **RFM** – Rate of Flow-Mod
- **PIRF** – % Irreversible Flows
- **PFSP** – % Small Packet Flows
- **PFSL** – % Short Lifetime Flows

### 4. mitigation2.py
Installs high-priority OpenFlow drop rules for malicious ports and MACs with timeout support.

---

## 🧠 Machine Learning

- **Model**: Support Vector Machine (SVM)
- **Features**: 5 engineered behavioral features
- **Prediction**: Every 2 seconds per active flow
- **Current Limitation**: No SHAP explainability or detailed validation metrics yet

---

## ⚔️ Attack Scripts

- `mac_injection_attack.py` — MAC spoofing with multiple fake MACs
- `dos_attack.py` — High-rate DoS / Packet-In flooding
- `stealth_attack.py` — Low-rate stealth reconnaissance

All attacks are implemented using **Scapy**.

---

## 🛠️ Installation

```bash
# Clone & Install
git clone <your-repo-url>
cd piedefender-v2

pip install -r requirements.txt

# Start Controller
ryu-manager controller/controller2.py --verbose
```

**Mininet Command:**
```bash
sudo mn --controller=remote,ip=127.0.0.1,port=6633 \
        --topo single,4 --switch ovsk,protocols=OpenFlow13
```

---

## 🚀 Usage

1. Start PIEDEFENDER controller
2. Launch Mininet topology
3. Generate normal traffic
4. Run attack scripts from attacker host
5. Monitor controller logs for detection and blocking

---

## 📊 Sample Output

```log
SWITCH CONNECTED dpid=1
PORT STATUS | dpid=1 port=3 reason=ADD
MAC INJECTION BLOCKED | dpid=1 port=3
DoS ATTACK BLOCKED | dpid=1 src=00:00:00:00:00:02
BLOCKED: Switch 1, Port 3
```

---

## 🔒 Security & Best Practices

- Use **only in isolated lab environments**
- Attack scripts are for research and testing only
- Consider TLS for OpenFlow in production
- Regular ML model retraining is recommended

---

## 📦 Dependencies

See `requirements.txt` (Ryu, Scapy, scikit-learn, joblib, etc.)

---

## 👥 Contributors

- **Samprit** - Primary Developer

---


---

**Copy everything above** (starting from `# PIEDEFENDER v2` till the end) and paste it into your README.md file.

If you want any changes (title, your name, repo link, etc.), just tell me.
