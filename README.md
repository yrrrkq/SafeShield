# SafeShield

> AI Sandbox + Web3 기반 스미싱·보이스피싱 위협 탐지 및 검증 시스템

SafeShield는 의심 URL을 **AI Sandbox로 분석**하고, 탐지된 위협 정보를 **블록체인에 등록한 뒤 다수 Validator의 검증을 통해 악성 여부를 확정**하는 시스템입니다.

기존의 기관별 분산된 위협 정보 공유 구조를 넘어, AI가 탐지한 위협을 여러 검증 주체가 확인하고 그 결과를 온체인에 기록하여 **신뢰 가능한 Threat Intelligence를 빠르게 공유하는 것**을 목표로 합니다.

---

## 1. SafeShield Demo

<img width="800" height="450" alt="safeshield_demo-ezgif com-video-to-gif-converter" src="https://github.com/user-attachments/assets/c96516f5-02bd-4d2d-8b16-a7d836d264a9" />




> 의심 URL 분석부터 AI 위험도 판별, 온체인 위협 검증 결과까지 확인할 수 있는 SafeShield 데모 화면입니다.

---

## 2. AI Sandbox

AI Sandbox는 URL에 직접 접속하여 수집한 기술적 증거와 AI 분석 결과를 결합해 위협도(Threat)를 판단합니다.

### Dynamic Analysis
- Playwright 기반 Headless Chromium 실행
- Redirect 추적
- DOM Text 추출
- 파일 Download 감지

### Static Analysis
- 다운로드 파일 SHA-256 Hash 계산
- APK/Manifest 분석
- Android 위험 Permission 탐지

### AI Analysis
- Gemini API 기반 피싱 문맥 분석
- 사칭 기관 및 사회공학 기법 분석
- 기술적 증거와 텍스트의 연관성 분석

```text
Dynamic Analysis
        +
Static Analysis
        +
AI / NLP Analysis
        ↓
Hybrid Risk Score (0~100)
```

고위험 Threat는 블록체인 검증 단계로 전달됩니다.

---

## 3. Blockchain Threat Validation

AI가 탐지한 위협(Threat) 정보은 Solidity 기반 `ThreatRegistry` Smart Contract에 등록됩니다.

Validator는 각자의 Wallet Account를 사용해 독립적으로:

```text
APPROVE (악성)
REJECT  (정상)
```

중 하나를 선택합니다.

과반수 Threshold는 Validator 수에 따라 자동 계산됩니다.

```text
threshold = validatorCount / 2 + 1
```

| Validators | Threshold |
|---:|---:|
| 3 | 2 |
| 4 | 3 |
| 5 | 3 |

과반수 APPROVE → `CONFIRMED`  
과반수 REJECT → `REJECTED`

`CONFIRMED`가 되면 `ThreatConfirmed` 이벤트가 발생하고 Event Listener가 이를 실시간으로 감지합니다.

> 현재 구현은 Threshold Signature/MPC가 아닌, Validator별 독립적인 온체인 서명 트랜잭션을 Smart Contract가 집계하는 **Threshold Validation** 구조입니다.

---

## 4. Why Blockchain?

SafeShield는 AI의 판단만으로 위협(Threat)을 즉시 확정하지 않습니다.

```text
AI Detection
      ↓
다수 기관 역할 Validator 검증
      ↓
On-chain 기록
      ↓
검증된 Threat Intelligence
```

이를 통해 단일 분석 주체에 의존하지 않고,

- 여러 검증 주체의 독립적인 판단
- 위협 검증 이력의 무결성
- 기관 간 공유 가능한 Threat Registry

를 구현합니다.

원본 APK나 분석 보고서 전체가 아닌 **URL Hash, APK Hash, Evidence Hash 등의 식별 정보와 검증 상태**를 온체인에 저장합니다.

---

## 5. Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React, Vite, Tailwind CSS |
| Backend | FastAPI, Python |
| Dynamic Analysis | Playwright |
| AI | Google Gemini API |
| Smart Contract | Solidity |
| Blockchain | Hardhat Local Network |
| Web3 Client | Ethers.js |
| Realtime | WebSocket, Event Listener |

---

## 6. Key Features

### AI / Sandbox
- 실제 브라우저 기반 URL 동적 분석
- Redirect / Download 탐지
- APK 정적 분석
- Gemini 기반 문맥 분석
- Hybrid Risk Score
- 안전한 Test Fixture 환경

### Blockchain
- Threat 온체인 등록
- Dynamic Validator
- Majority Threshold 자동 계산
- APPROVE / REJECT 검증
- 중복 투표 방지
- `PENDING / CONFIRMED / REJECTED` 상태 관리
- `ThreatConfirmed` Event 및 Listener

---

## 7. Blockchain Demo

블록체인 데모는 **3개의 Terminal**을 사용하여 Local Blockchain, Validator 투표, Event 감지를 동시에 실행합니다.

### Terminal 1 — Local Blockchain

Hardhat Local Network를 실행합니다.  
Smart Contract 배포와 Validator Transaction이 처리되는 로컬 블록체인 환경입니다.

```bash
npx hardhat node
```

이 Terminal은 데모가 끝날 때까지 실행 상태를 유지합니다.

---

### Terminal 2 — Deploy / Submit / Vote

Smart Contract를 배포하고, Threat 등록 및 Validator 투표를 진행합니다.

Contract 배포:

```bash
node scripts/deployThreatRegistry.js
```

실행 시 Validator로 사용할 Account를 선택하며, Validator 수에 따라 과반수 Threshold가 자동 계산됩니다.

Threat 등록:

```bash
node scripts/submitThreat.js http://malicious-example.com/test
```

등록 후 출력되는 `Threat ID`를 사용하여 Validator 투표를 진행합니다.

```bash
node scripts/approveThreat.js <THREAT_ID>
```

각 Validator는 `APPROVE(악성)` 또는 `REJECT(정상)` 중 하나를 선택합니다.

---

### Terminal 3 — Event Listener

Smart Contract에서 발생하는 `ThreatConfirmed` 이벤트를 실시간으로 감지합니다.

```bash
node scripts/listener.js
```

과반수 Validator가 APPROVE하면:

```text
Status: CONFIRMED
Blacklisted: true
```

가 되고, Terminal 3에서 `ThreatConfirmed` 이벤트를 확인할 수 있습니다.

---

### Test

Smart Contract의 Threat 등록, Validator 검증, 상태 변경 등의 핵심 로직을 테스트합니다.

```bash
npx hardhat test
```



