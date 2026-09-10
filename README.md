# SafeShield: AI Sandbox & Web3 On-Chain Threat Sharing System
> **Real-Time Zero-Day Smishing & Voice Phishing Prevention via Headless AI Sandbox and Decentralized Multi-Sig Threat Oracle**

---

## 🌟 Overview & Architecture

SafeShield is an end-to-end decentralized cybersecurity system that intercepts smishing SMS messages and malicious voice phishing APK downloads before victims can execute them.

```
+---------------------------+        +-----------------------------------+
| 1. Victim Mobile (Smishing)| -----> | 2. AI Headless Sandbox (FastAPI)  |
|  - SMS Link Intercept     |        |  - Playwright Headless Browser    |
|  - Auto-Download Detect   |        |  - Static Bytecode Decompilation  |
+---------------------------+        |  - APK SHA-256 Hash Extraction    |
                                     |  - Android Permission Risk Score  |
                                     +-----------------------------------+
                                                      |
                                                      v
+-----------------------------------+        +-----------------------------------+
| 4. Global Broadcast (1-Second)    | <----- | 3. Smart Contract Threat Oracle   |
|  - Instant Block on Mobile Agents |        |  - SafeShieldOracle.sol (EVM)     |
|  - Banking SDK Blacklist Sync     |        |  - 2-of-4 Multi-Sig Consensus     |
|  - Telecom Carrier DNS Blocking   |        |  - KISA, AhnLab, Police, FSS Nodes|
+-----------------------------------+        +-----------------------------------+
```

---

## 🚀 Key Features

1. **Multi-Sig Oracle Smart Contract (`contracts/SafeShieldOracle.sol`)**:
   - Stores malicious APK/URL SHA-256 hashes on EVM testnet/mainnet.
   - Requires $\ge 2$ independent signatures from authorized cybersecurity nodes (KISA, AhnLab, National Police Agency, FSS).
   - Emits `MalwareConfirmed(bytes32 indexed apkHash, string url)` on consensus.

2. **AI Sandbox & Static Decompiler (`backend/main.py`, `backend/analyzer.py`)**:
   - Navigates suspicious URLs using Playwright Headless Chrome with Android User-Agent.
   - Intercepts auto-triggering `.apk` payload downloads.
   - Extracts true SHA-256 fingerprint.
   - Decompiles `AndroidManifest.xml` to flag critical permissions (`BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`, `READ_SMS`, `CALL_PHONE`, `RECORD_AUDIO`).
   - Automatically proposes threat to on-chain oracle if Risk Score $\ge 70$.

3. **Interactive 3-Panel Cybersecurity Command Dashboard (`frontend/src/App.jsx`)**:
   - **Left Panel**: Realistic Smartphone UI mock receiving smishing SMS messages across 4 real-world presets (CJ Courier delivery scam, Mobile wedding card, Gov loan grant scam, Fake police wiretap app).
   - **Middle Panel**: Real-time cyber terminal streaming sandbox events, Playwright DOM inspection, permission flags, and live multi-sig signature progress.
   - **Right Panel**: Web3 on-chain threat ledger displaying pending and confirmed zero-day malware records with 1-second global broadcast flash alerts.

---

## 🛠️ Quick Start & Running the Project

### 1. Smart Contract (Solidity & Hardhat)
```bash
# In the project root
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
npx hardhat compile
npx hardhat run scripts/deploy.js
```

### 2. Python AI Sandbox Backend (FastAPI)
```bash
cd backend
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
playwright install chromium
python main.py
# Server runs on http://localhost:8000
```

### 3. React / Next.js / Vite Frontend
```bash
cd frontend
npm install
npm run dev
# Dashboard opens on http://localhost:3000
```

---

## 🧪 Testing the Smishing Scenarios

1. Open `http://localhost:3000` in your browser.
2. Select any preset scenario (e.g., **CJ 대한통운 배송조회** or **경찰청 안심보안앱 사칭**).
3. Click the link inside the SMS or click **"⚡ Simulate User Clicking Link"**.
4. Observe the **Middle Panel** stream real-time logs (Chromium launch, APK intercept, SHA-256 hashing, dangerous permission breakdown).
5. Watch the **Multi-Sig Oracle Consensus** reach 2-of-2 signatures (KISA + AhnLab).
6. Experience the **1-Second Global Flash Broadcast** alert across the top of the dashboard.
7. Note how the **Smartphone Shield** transitions to **"⚠️ THREAT INTERCEPTED ON-CHAIN"**, blocking execution in real time!
