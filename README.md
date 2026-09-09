# 1) Threat Intelligence Blockchain

AI Sandbox에서 탐지한 보이스피싱·스미싱 위협 정보를 블록체인에 등록하고, 복수의 기관 Validator가 검증하여 악성 여부를 확정하는 **블록체인 기반 위협 정보 검증·공유 시스템**입니다.

단일 기관의 판단만으로 위협 정보를 확정하지 않고, 3개의 Validator 중 2개 이상의 승인을 요구하는 **2-of-3 Threshold Validation** 구조를 적용했습니다.

검증을 통해 악성 위협이 최종 확정되면 `ThreatConfirmed` 이벤트를 발생시켜 외부 시스템이 확정 정보를 감지하고 활용할 수 있도록 구현했습니다.


## 2) 핵심 구현 기능

- AI 분석 결과 기반 Threat Report 온체인 등록
- URL / APK / Evidence Hash 기반 위협 식별
- 기관 역할별 Validator 검증
- 2-of-3 Threshold Validation
- PENDING / CONFIRMED / REJECTED 상태 관리
- 확정 악성 위협 Blacklist 관리
- 동일 Validator의 중복 투표 방지
- 비인가 계정의 검증 참여 방지
- `ThreatConfirmed` Event 발생 및 Listener 감지


## 3) 전체 동작 흐름

```text
AI Sandbox
     │
     │ Threat Report
     ▼
ThreatRegistry
     │
     │ submitThreat()
     ▼
   PENDING
     │
     ▼
Validator Layer
 ├─ KISA 역할 Validator
 ├─ Police 역할 Validator
 └─ AhnLab 역할 Validator
     │
     │ 2-of-3 Threshold Validation
     ▼
  CONFIRMED
     │
     ├── Blacklist 등록
     │
     └── ThreatConfirmed Event
                 │
                 ▼
          Event Listener
                 │
                 ▼
         Backend / Client
```


## 4) Blockchain Architecture

### 1. Threat 등록

AI Sandbox의 분석 결과를 기반으로 Threat Report를 생성하고 `ThreatRegistry` Smart Contract에 등록합니다.

주요 데이터 구조는 다음과 같습니다.

```text
urlHash
apkHash
evidenceHash
c2
riskScore
approveCount
rejectCount
status
createdAt
```

URL 및 분석 Evidence 등은 원본 데이터를 그대로 저장하지 않고 Hash 형태로 변환하여 등록합니다.


### 2. Validator 검증

등록된 Threat는 최초 `PENDING` 상태로 저장됩니다.

3개의 Validator가 각각 위협 정보에 대해 승인 또는 거절할 수 있으며, 동일 Validator는 하나의 Threat에 중복 투표할 수 없습니다.

현재 구현에서는 기관 간 검증 구조를 표현하기 위해 Hardhat 테스트 계정에 다음과 같은 Validator 역할을 부여했습니다.

```text
Validator 1 → KISA 역할
Validator 2 → Police 역할
Validator 3 → AhnLab 역할
```

※ 위 기관명은 기관 간 위협 정보 검증 구조를 구현하기 위한 Validator 역할명이며, 실제 기관 시스템과 연동된 계정은 아닙니다.


### 3. 2-of-3 Threshold Validation

2개 이상의 Validator가 승인하면:

```text
PENDING
   ↓
CONFIRMED
   ↓
Blacklisted = true
```

2개 이상의 Validator가 거절하면:

```text
PENDING
   ↓
REJECTED
```

이를 통해 하나의 Validator 판단만으로 위협의 최종 상태가 결정되지 않도록 구성했습니다.


### 4. ThreatConfirmed Event

2-of-3 승인 조건이 충족되면 Smart Contract에서 `ThreatConfirmed` 이벤트가 발생합니다.

```solidity
event ThreatConfirmed(
    bytes32 indexed threatId,
    bytes32 urlHash,
    bytes32 apkHash
);
```

Event Listener는 해당 이벤트를 감지하여 확정된 위협 정보를 외부 시스템에서 활용할 수 있도록 전달 지점을 제공합니다.


## Threat 상태

| Value | Status | 설명 |
|---|---|---|
| 0 | NONE | 등록되지 않은 위협 |
| 1 | PENDING | Validator 검증 대기 |
| 2 | CONFIRMED | 2-of-3 승인으로 악성 확정 |
| 3 | REJECTED | 2-of-3 거절로 검증 거절 |


## 5) 기술 스택

| Category | Technology |
|---|---|
| Smart Contract | Solidity 0.8.20 |
| Blockchain Development | Hardhat |
| Blockchain Interaction | Ethers.js |
| Runtime | Node.js |
| Test | Mocha / TypeScript |


## 6) 프로젝트 구조

```text
BlockChain/
│
├── contracts/
│   └── ThreatRegistry.sol
│
├── scripts/
│   ├── deploy.js
│   ├── submitThreat.js
│   ├── approveThreat.js
│   └── listener.js
│
├── backend/
│   └── blockchain.js
│
├── test/
│   └── ThreatRegistry.test.ts
│
├── hardhat.config.js
├── package.json
└── README.md
```


## 7) 테스트

Smart Contract의 주요 위협 등록 및 검증 로직에 대한 자동 테스트를 구성했습니다.

```bash
npx hardhat test
```

### 테스트 항목

- Validator 등록 확인
- Threat 등록 및 PENDING 상태 확인
- 1개 Validator 승인 후 PENDING 유지
- 2개 Validator 승인 후 CONFIRMED 전환
- CONFIRMED Threat의 Blacklist 등록 확인
- 2개 Validator 거절 후 REJECTED 전환
- 동일 Validator 중복 투표 방지
- 비인가 계정의 투표 방지


# 8) 실행 방법

현재 블록체인 검증 환경은 **Hardhat Local Network**를 기반으로 구성되어 있습니다.

아래 순서에 따라 Threat 등록 → Validator 검증 → Threat 확정 → Event 감지 과정을 실행할 수 있습니다.


## 1. 설치

Repository를 Clone합니다.

```bash
git clone https://github.com/yrrrkq/blockchain.git
cd blockchain
git checkout dev/blockchain
```

필요한 패키지를 설치합니다.

```bash
npm install
```

Smart Contract를 컴파일합니다.

```bash
npx hardhat compile
```

필요한 경우 테스트를 실행합니다.

```bash
npx hardhat test
```


## 2. Terminal 1 - Hardhat Network 실행

첫 번째 터미널에서 Local Blockchain을 실행합니다.

```bash
npx hardhat node
```

기본 RPC:

```text
http://127.0.0.1:8545
```

이 터미널은 전체 실행 과정 동안 유지합니다.


## 3. Terminal 2 - Smart Contract 배포

두 번째 터미널에서 `ThreatRegistry`를 배포합니다.

```bash
npx hardhat run scripts/deploy.js --network localhost
```

배포가 완료되면 Validator 주소와 Contract Address가 출력됩니다.

```text
Deployer: 0x...
KISA: 0x...
Police: 0x...
AhnLab: 0x...

ThreatRegistry deployed!
Contract address: 0x...
```


## 4. Terminal 2 - Event Listener 실행

Smart Contract 배포 후 Event Listener를 실행합니다.

```bash
node scripts/listener.js
```

정상적으로 연결되면 다음과 같이 출력됩니다.

```text
ThreatConfirmed Event Listener
Waiting for confirmed threats...
```

이 상태에서 Listener는 `ThreatConfirmed` 이벤트 발생을 기다립니다.


## 5. Terminal 3 - Threat 등록

세 번째 터미널에서 새로운 Threat를 등록합니다.

```bash
node scripts/submitThreat.js http://malicious-example.com/test
```

현재 스크립트에서는 AI Sandbox의 분석 결과를 가정하여 Threat Report를 생성합니다.

등록이 완료되면 다음과 같이 Blockchain Transaction과 Threat ID를 확인할 수 있습니다.

```text
Threat submitted!

Transaction hash: 0x...

Threat ID: 0x...
Risk Score: 92
Approve Count: 0
Reject Count: 0
Status: 1
```

`Status: 1`은 Validator의 검증을 기다리는 `PENDING` 상태입니다.


## 6. Terminal 3 - Validator 검증

Threat 등록 시 출력된 `Threat ID`를 사용합니다.

```bash
node scripts/approveThreat.js <THREAT_ID>
```

예:

```bash
node scripts/approveThreat.js 0x...
```

첫 번째 Validator가 승인하면:

```text
KISA approval complete
Approve Count: 1
Status: 1
```

아직 2-of-3 조건을 충족하지 않았으므로 `PENDING` 상태를 유지합니다.

두 번째 Validator가 승인하면:

```text
Police approval complete
Approve Count: 2
Status: 2
```

최종 결과:

```text
Approve Count: 2
Status: 2
Blacklisted: true
```

2개의 Validator 승인을 통해 Threat가 `CONFIRMED` 상태로 전환됩니다.


## 7. ThreatConfirmed Event 확인

2-of-3 승인 조건이 충족되면 Smart Contract에서 `ThreatConfirmed` 이벤트가 발생합니다.

앞서 실행한 Terminal 2의 Event Listener에서 다음과 같이 확정된 Threat를 확인할 수 있습니다.

```text
THREAT CONFIRMED
---------------------------------
Threat ID: 0x...
URL Hash: 0x...
APK Hash: 0x...
---------------------------------
Threat added to blacklist
Ready to broadcast to clients
```

이를 통해 다음 흐름을 확인할 수 있습니다.

```text
Threat 등록
   ↓
PENDING
   ↓
Validator 검증
   ↓
2-of-3 승인
   ↓
CONFIRMED
   ↓
Blacklist
   ↓
ThreatConfirmed Event
   ↓
Event Listener 감지
```