# ThreatRegistry Blockchain

AI Sandbox가 탐지한 보이스피싱·스미싱 의심 위협 정보를 블록체인에 등록하고,  
다수의 Validator가 독립적으로 검증하여 악성 여부를 확정하는 온체인 Threat Intelligence Registry입니다.

## 1. System Flow

```text
AI Sandbox
    ↓
Threat Report 생성
    ↓
ThreatRegistry 등록
    ↓
PENDING
    ↓
Validator 검증
    ├─ APPROVE
    └─ REJECT
    ↓
과반수 기반 Threshold Validation
    ↓
CONFIRMED / REJECTED
    ↓
ThreatConfirmed Event
    ↓
Event Listener
    ↓
Backend / Client 전달
```

현재 MVP에서는 Hardhat Local Network를 사용하여  
위협 등록 → Validator 검증 → 상태 확정 → 이벤트 전달까지의 흐름을 구현합니다.

---

## 2. Threat Data

AI Sandbox의 분석 결과 전체를 블록체인에 저장하지 않고,  
위협 검증에 필요한 Hash 및 메타데이터를 저장합니다.

- URL Hash
- APK Hash
- Evidence Hash
- C2
- Risk Score
- Approve Count
- Reject Count
- Status
- Created At

원본 URL, APK, 분석 보고서 전체를 직접 온체인에 저장하지 않고 Hash를 활용하여  
위협 데이터의 식별 및 무결성 검증에 활용합니다.

---

## 3. Threat Status

Threat는 다음 상태를 가집니다.

| Status | 설명 |
|---|---|
| `NONE` | 등록되지 않은 Threat |
| `PENDING` | Validator 검증 대기 |
| `CONFIRMED` | 과반수 APPROVE로 악성 확정 |
| `REJECTED` | 과반수 REJECT로 정상 판정 |

### CONFIRMED

Validator의 APPROVE 수가 과반수 임계값에 도달하면 `CONFIRMED` 상태가 됩니다.

이때 `ThreatConfirmed` 이벤트가 발생하며,  
해당 Threat는 `isBlacklisted()`를 통해 Blacklist 대상으로 조회할 수 있습니다.

### REJECTED

Validator의 REJECT 수가 과반수 임계값에 도달하면 `REJECTED` 상태가 됩니다.

REJECTED Threat는 Blacklist에 포함되지 않습니다.

---

## 4. Dynamic Validator System

Validator는 컨트랙트 배포 시 사용할 Account를 자유롭게 선택할 수 있습니다.

예를 들어:

```text
3 Validators → Threshold 2
4 Validators → Threshold 3
5 Validators → Threshold 3
6 Validators → Threshold 4
```

과반수 임계값은 Smart Contract에서 자동으로 계산합니다.

```text
threshold = validatorCount / 2 + 1
```

각 Validator는 자신의 Wallet Account를 이용해  
Threat에 대해 독립적으로 `APPROVE` 또는 `REJECT` 트랜잭션을 전송합니다.

동일한 Validator는 하나의 Threat에 한 번만 투표할 수 있습니다.

> 현재 구현은 Threshold Signature 또는 MPC 방식이 아닙니다.  
> 각 Validator가 개별적으로 서명한 온체인 트랜잭션을 기반으로  
> Smart Contract가 과반수 여부를 판단하는 Threshold Validation 구조입니다.

---

## 5. Project Structure

```text
backend/
└── blockchain.js

contracts/
└── ThreatRegistry.sol

scripts/
├── deploy.js
├── submitThreat.js
├── approveThreat.js
└── listener.js

test/
└── ThreatRegistry.test.ts
```

### `ThreatRegistry.sol`

- Threat 등록
- Validator 관리
- APPROVE / REJECT 투표
- 과반수 Threshold 계산
- Threat 상태 관리
- 중복 투표 방지
- Blacklist 조회
- `ThreatConfirmed` 이벤트 발생

### `deploy.js`

Hardhat Local Network에 `ThreatRegistry`를 배포합니다.

실행 시 Validator로 사용할 Account를 직접 선택할 수 있으며,  
선택된 Validator 수에 따라 과반수 Threshold가 자동 계산됩니다.

배포 후 다음 정보가 `deployment.json`에 자동 저장됩니다.

- Contract Address
- Validator Count
- Threshold
- Validator Account 정보

`deployment.json`은 로컬 실행 환경에서 자동 생성되는 파일이므로 Git에는 포함하지 않습니다.

### `backend/blockchain.js`

AI 분석 결과를 `ThreatRegistry.submitThreat()`로 전달합니다.

`deployment.json`을 읽어 가장 최근에 배포된 Contract Address에 자동으로 연결합니다.

### `submitThreat.js`

AI Sandbox의 Threat Report를 가정하여 테스트 Threat를 블록체인에 등록합니다.

### `approveThreat.js`

등록된 Validator Account 중 하나를 선택한 뒤 Threat에 대해:

```text
[1] APPROVE (악성)
[2] REJECT  (정상)
```

중 하나를 선택하여 투표합니다.

### `listener.js`

`ThreatConfirmed` 이벤트를 실시간으로 감지합니다.

향후 Backend API, WebSocket, Client 또는 보안 솔루션에  
확정된 위협 정보를 전달하기 위한 연결 지점으로 사용합니다.

---

## 6. Setup

### Install

```bash
npm install
```

### Compile

```bash
npx hardhat compile
```

### Test

```bash
npx hardhat test
```

---

## 7. Run

전체 테스트는 터미널 3개를 사용합니다.

### Terminal 1 - Hardhat Local Network

```bash
npx hardhat node
```

Hardhat Local Network를 실행합니다.

이 터미널은 테스트가 끝날 때까지 종료하지 않습니다.

---

### Terminal 2 - Deploy

```bash
node scripts/deploy.js
```

실행하면 Hardhat Account 목록이 출력됩니다.

예:

```text
Validator로 사용할 Account 번호를 입력하세요 (예: 1,2,3): 1,2,3,4,5
```

5개의 Validator를 선택한 경우:

```text
Validator count: 5
Majority threshold: 3
```

으로 자동 설정됩니다.

배포된 Contract Address는 `deployment.json`에 자동 저장됩니다.

---

### Terminal 3 - Event Listener

```bash
node scripts/listener.js
```

Listener가 `ThreatConfirmed` 이벤트를 기다립니다.

```text
ThreatConfirmed Event Listener
Waiting for confirmed threats...
```

Listener를 실행한 상태에서 이후 Threat 등록 및 Validator 투표를 진행합니다.

---

### Terminal 2 - Submit Threat

```bash
node scripts/submitThreat.js http://malicious-example.com/test
```

정상적으로 등록되면 Threat ID와 현재 상태가 출력됩니다.

```text
Threat ID: 0x...
Risk Score: 92
Approve Count: 0
Reject Count: 0
Status: 1
```

`Status: 1`은 `PENDING` 상태입니다.

---

### Terminal 2 - Validator Vote

위에서 생성된 Threat ID를 사용합니다.

```bash
node scripts/approveThreat.js <THREAT_ID>
```

실행 후 투표할 Validator Account를 선택합니다.

```text
투표할 Validator Account 번호를 입력하세요:
```

그다음 판정을 선택합니다.

```text
[1] APPROVE (악성)
[2] REJECT (정상)
선택:
```

과반수에 도달하기 전에는:

```text
Approve Count: 1
Reject Count: 0
Status: PENDING
Blacklisted: false
```

상태를 유지합니다.

과반수의 Validator가 APPROVE하면:

```text
Status: CONFIRMED
Blacklisted: true
```

가 되며 `ThreatConfirmed` 이벤트가 발생합니다.

실행 중인 Terminal 3의 Listener가 해당 이벤트를 감지합니다.

---

## 8. Current MVP Scope

### 구현 완료

- AI Threat Report 온체인 등록
- Hash 기반 Threat 정보 저장
- 배포 시 Validator 동적 선택
- Validator 수에 따른 과반수 Threshold 자동 계산
- Validator별 독립적인 APPROVE / REJECT
- 동일 Validator 중복 투표 방지
- `PENDING / CONFIRMED / REJECTED` 상태 관리
- Blacklist 조회
- `ThreatConfirmed` Event 발생
- Event Listener를 통한 실시간 이벤트 감지
- 최신 배포 Contract Address 자동 연동

### 향후 확장

현재 MVP에서는 실제 브라우저 또는 사용자 단말의 URL 접근 차단까지는 구현하지 않습니다.

향후 다음과 같은 구조로 확장할 수 있습니다.

```text
ThreatConfirmed
      ↓
Event Listener
      ↓
Backend
      ↓
API / WebSocket / Threat Feed
      ↓
금융기관 · 통신사 · 보안 솔루션 · Client
      ↓
악성 URL / APK 접근 차단
```

이를 통해 온체인에서 검증·확정된 Threat Intelligence를  
외부 보안 시스템의 실시간 차단 데이터로 활용할 수 있습니다.
