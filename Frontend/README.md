# SysSec: Real-Time Syscall Anomaly Detection

**SysSec** is a kernel-level intrusion detection system (IDS) that uses a Probabilistic Context-Free Grammar (PCFG) machine learning model to monitor Linux system calls in real-time. It learns the "normal" behavior of a target application and instantly detects anomalies like Remote Code Execution (RCE), Path Traversals, and Zero-Day memory exploits by analyzing deviations in the system call sequence grammar.

![SysSec Dashboard Concept](https://img.shields.io/badge/Status-Hackathon_Ready-success) ![Python](https://img.shields.io/badge/Python-3.10+-blue) ![React](https://img.shields.io/badge/React-Vite-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-WebSockets-green)

---

## 🏗 System Architecture

The project consists of 4 main pillars:

1. **`TEST_SERVER/` (The Target)**: A dummy Node.js/Express file management backend. It contains *intentionally vulnerable routes* to demonstrate attacks.
2. **`Components/` (The ML Core)**: Python scripts that collect system call traces via `strace`/`perf`, train the PCFG model, and actively monitor the target process.
3. **`Backend/` (The Relay)**: A fast asynchronous Python (FastAPI) server that ingests raw syscalls and anomalies via WebSockets from the monitor, broadcasting them to the dashboard.
4. **`Frontend/` (The Dashboard)**: A modern React application that visualizes the live syscall feed, renders real-time anomaly alerts, and displays interactive parse trees to explain *why* an anomaly triggered.

---

## 🧠 How the ML Model Works
The system uses an **N-Gram Scorer** with Laplace smoothing built on top of a **PCFG (Probabilistic Context-Free Grammar)**.
1. `Sequitur` compresses normal sequences into a hierarchical grammar.
2. The `train.py` script counts transition probabilities between syscalls.
3. The `NGramScorer` assigns an anomaly score based on the mean negative log probability of the bigram transitions in a live cycle.
4. **Laplace smoothing** ensures the model doesn't break on completely unknown syscalls, but correctly assigns them a massive penalty.
5. The frontend utilizes the **Inside Algorithm (CYK)** purely to generate a visual parse tree breakdown of where the sequence failed.

---

## 🚀 Foolproof Quickstart Guide

You will need **5 Terminal windows** to run the full pipeline. Ensure you are using a Linux environment (required for `strace` and system calls) and have your Conda environment (`syssec`) active in the Python terminals.

### Step 1: Start the Vulnerable Target Server
Start the Node.js backend that we will be monitoring and attacking.
```bash
# Terminal 1
cd TEST_SERVEER/backend
npm install
node server.js
```
*Note the PID (Process ID) of the node server. You can find it by running `pgrep -f "node server.js"` in another terminal.*

### Step 2: Start the Anomaly Dashboard (Backend & Frontend)
Start the systems responsible for visualizing the data.

```bash
# Terminal 2 (FastAPI Backend)
cd Backend
pip install -r requirements.txt
python syscall_anomaly_server.py
# Runs on http://127.0.0.1:8000
```

```bash
# Terminal 3 (React Frontend)
cd Frontend
npm install
npm run dev
# Runs on http://localhost:5173
```
*Open `http://localhost:5173` in your browser. It will say "Awaiting connection..."*

### Step 3: Train the Machine Learning Model (Baseline)
We need to teach the model what "normal" looks like. Attach the collector to the running Node server.
```bash
# Terminal 4
cd Components

# 1. Collect Normal Traces (Replace <PID> with your Node server's PID)
python collect_traces.py <PID> normal_traces.pkl --strace

# -> While it is running, click around the normal parts of the TEST_SERVER app (register, login, upload a file). 
# -> Press Ctrl+C when you have ~50-100 traces.

# 2. Train the Model
python train.py normal_traces.pkl my_model.pkl
```

### Step 4: Attach the Live Monitor
Attach the live intrusion detector to the target process. It will stream data to the dashboard.
```bash
# Terminal 4 (Continued)
python cyclic_monitoring.py \
    --pid <PID> \
    --model my_model.pkl \
    --strace \
    --send-api http://127.0.0.1:8000
```
*Your frontend dashboard will now light up with a live feed of system calls!*

---

## 💥 How to Demo Attacks (Triggering Anomalies)

The `TEST_SERVER` has hidden routes (`/api/vuln/...`) explicitly designed to simulate advanced attacks. 
Run these commands in a 5th terminal. Watch your dashboard instantly catch them!

### 1. Remote Code Execution (Command Injection)
Forces the Node event loop to spawn a shell (`execve`, `clone`), shattering the normal grammar.
```bash
curl -X POST -H "Content-Type: application/json" -d '{"host": "127.0.0.1; whoami && ls -la"}' http://localhost:5000/api/vuln/ping
```

### 2. Local File Inclusion (Path Traversal)
Reads protected OS files, causing `openat` to fail with `EACCES` and generating unexpected error-handling syscalls.
```bash
curl "http://localhost:5000/api/vuln/read?file=/etc/shadow"
```

### 3. Server-Side Request Forgery (SSRF)
Forces the server to make outbound network requests, triggering `socket` and `connect` calls not seen during standard API hosting.
```bash
curl -X POST -H "Content-Type: application/json" -d '{"url": "http://127.0.0.1:22"}' http://localhost:5000/api/vuln/fetch
```

### 4. Zero-Day (Malware Dropper Simulation)
Simulates an attacker writing a payload to disk, making it executable, and running it.
```bash
curl -X POST http://localhost:5000/api/vuln/zeroday
```

### 5. Memory Exhaustion (DoS)
Forces the backend to request gigabytes of RAM, spamming the kernel with `mmap` and `brk` allocations.
```bash
curl -X POST http://localhost:5000/api/vuln/dos
```

### 6. Reverse Shell Simulation (C2)
Simulates connecting back to an attacker's machine and binding standard I/O to a network socket via `dup2`.
```bash
curl -X POST -H "Content-Type: application/json" -d '{"ip": "127.0.0.1", "port": 4444}' http://localhost:5000/api/vuln/revshell
```




# SysSec: Real-Time Syscall Anomaly Detection

**SysSec** is a kernel-level intrusion detection system (IDS) that uses a Probabilistic Context-Free Grammar (PCFG) machine learning model to monitor Linux system calls in real-time. It learns the "normal" behavior of a target application and instantly detects anomalies like Remote Code Execution (RCE), Path Traversals, and Zero-Day memory exploits by analyzing deviations in the system call sequence grammar.

![SysSec Dashboard Concept](https://img.shields.io/badge/Status-Hackathon_Ready-success) ![Python](https://img.shields.io/badge/Python-3.10+-blue) ![React](https://img.shields.io/badge/React-Vite-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-WebSockets-green)

---

## 🏗 System Architecture

The project consists of 4 main pillars:

1. **`TEST_SERVER/` (The Target)**: A dummy Node.js/Express file management backend. It contains *intentionally vulnerable routes* to demonstrate attacks.
2. **`Components/` (The ML Core)**: Python scripts that collect system call traces via `strace`/`perf`, train the PCFG model, and actively monitor the target process.
3. **`Backend/` (The Relay)**: A fast asynchronous Python (FastAPI) server that ingests raw syscalls and anomalies via WebSockets from the monitor, broadcasting them to the dashboard.
4. **`Frontend/` (The Dashboard)**: A modern React application that visualizes the live syscall feed, renders real-time anomaly alerts, and displays interactive parse trees to explain *why* an anomaly triggered.

---

## 🧠 How the ML Model Works
The system uses an **N-Gram Scorer** with Laplace smoothing built on top of a **PCFG (Probabilistic Context-Free Grammar)**.
1. `Sequitur` compresses normal sequences into a hierarchical grammar.
2. The `train.py` script counts transition probabilities between syscalls.
3. The `NGramScorer` assigns an anomaly score based on the mean negative log probability of the bigram transitions in a live cycle.
4. **Laplace smoothing** ensures the model doesn't break on completely unknown syscalls, but correctly assigns them a massive penalty.
5. The frontend utilizes the **Inside Algorithm (CYK)** purely to generate a visual parse tree breakdown of where the sequence failed.

---

## 🚀 Foolproof Quickstart Guide

You will need **5 Terminal windows** to run the full pipeline. Ensure you are using a Linux environment (required for `strace` and system calls) and have your Conda environment (`syssec`) active in the Python terminals.

### Step 1: Start the Vulnerable Target Server
Start the Node.js backend that we will be monitoring and attacking.
```bash
# Terminal 1
cd TEST_SERVEER/backend
npm install
node server.js
```
*Note the PID (Process ID) of the node server. You can find it by running `pgrep -f "node server.js"` in another terminal.*

### Step 2: Start the Anomaly Dashboard (Backend & Frontend)
Start the systems responsible for visualizing the data.

```bash
# Terminal 2 (FastAPI Backend)
cd Backend
pip install -r requirements.txt
python syscall_anomaly_server.py
# Runs on http://127.0.0.1:8000
```

```bash
# Terminal 3 (React Frontend)
cd Frontend
npm install
npm run dev
# Runs on http://localhost:5173
```
*Open `http://localhost:5173` in your browser. It will say "Awaiting connection..."*

### Step 3: Train the Machine Learning Model (Baseline)
We need to teach the model what "normal" looks like. Attach the collector to the running Node server.
```bash
# Terminal 4
cd Components

# 1. Collect Normal Traces (Replace <PID> with your Node server's PID)
python collect_traces.py <PID> normal_traces.pkl --strace

# -> While it is running, click around the normal parts of the TEST_SERVER app (register, login, upload a file). 
# -> Press Ctrl+C when you have ~50-100 traces.

# 2. Train the Model
python train.py normal_traces.pkl my_model.pkl
```

### Step 4: Attach the Live Monitor
Attach the live intrusion detector to the target process. It will stream data to the dashboard.
```bash
# Terminal 4 (Continued)
python cyclic_monitoring.py \
    --pid <PID> \
    --model my_model.pkl \
    --strace \
    --send-api http://127.0.0.1:8000
```
*Your frontend dashboard will now light up with a live feed of system calls!*

---

## 💥 How to Demo Attacks (Triggering Anomalies)

The `TEST_SERVER` has hidden routes (`/api/vuln/...`) explicitly designed to simulate advanced attacks. 
Run these commands in a 5th terminal. Watch your dashboard instantly catch them!

### 1. Remote Code Execution (Command Injection)
Forces the Node event loop to spawn a shell (`execve`, `clone`), shattering the normal grammar.
```bash
curl -X POST -H "Content-Type: application/json" -d '{"host": "127.0.0.1; whoami && ls -la"}' http://localhost:5000/api/vuln/ping
```

### 2. Local File Inclusion (Path Traversal)
Reads protected OS files, causing `openat` to fail with `EACCES` and generating unexpected error-handling syscalls.
```bash
curl "http://localhost:5000/api/vuln/read?file=/etc/shadow"
```

### 3. Server-Side Request Forgery (SSRF)
Forces the server to make outbound network requests, triggering `socket` and `connect` calls not seen during standard API hosting.
```bash
curl -X POST -H "Content-Type: application/json" -d '{"url": "http://127.0.0.1:22"}' http://localhost:5000/api/vuln/fetch
```

### 4. Zero-Day (Malware Dropper Simulation)
Simulates an attacker writing a payload to disk, making it executable, and running it.
```bash
curl -X POST http://localhost:5000/api/vuln/zeroday
```

### 5. Memory Exhaustion (DoS)
Forces the backend to request gigabytes of RAM, spamming the kernel with `mmap` and `brk` allocations.
```bash
curl -X POST http://localhost:5000/api/vuln/dos
```

### 6. Reverse Shell Simulation (C2)
Simulates connecting back to an attacker's machine and binding standard I/O to a network socket via `dup2`.
```bash
curl -X POST -H "Content-Type: application/json" -d '{"ip": "127.0.0.1", "port": 4444}' http://localhost:5000/api/vuln/revshell
```