# SafeShield

> AI Sandbox + Web3 기반 스미싱·보이스피싱 위협 탐지 및 검증 시스템
> <img width="1597" height="892" alt="image" src="https://github.com/user-attachments/assets/fc97f486-1394-4c14-86cb-5e07b214dae4" />


SafeShield는 의심 URL을 **AI Sandbox에서 분석**하고, 탐지된 위협 정보를 **블록체인에 등록한 뒤 다수 Validator의 검증을 통해 악성 여부를 확정**하는 시스템입니다.

기존의 기관별 분산된 위협 정보 공유 구조를 넘어, AI가 탐지한 위협을 여러 검증 주체가 확인하고 그 결과를 온체인에 기록하여 **신뢰 가능한 Threat Intelligence를 빠르게 공유하는 것**을 목표로 합니다.

---

## 1. SafeShield Demo

<img width="800" height="450" alt="safeshield_demo-ezgif com-video-to-gif-converter" src="https://github.com/user-attachments/assets/718edbe5-f6d5-4b6f-be43-1daefc58b901" />




 
 >의심 URL 분석부터 AI 위험도 판별, 온체인 위협 검증 결과까지 확인할 수 있는 SafeShield 데모 화면입니다.
---

## 2. AI Sandbox

AI Sandbox는 URL에 직접 접속하여 수집한 기술적 증거와 AI 분석 결과를 결합해 위협도(Threat)를 판단합니다.
| AI 위협 분석 리포트 | AI 분석 결과 상세 |
| :---: | :---: |
| <img src="https://github.com/user-attachments/assets/650817dd-98e2-4210-be62-7d7bb031fac2" width="100%"> | <img src="https://github.com/user-attachments/assets/bf1bb5f1-601c-41d4-93b9-840d28eeb4fe" width="100%"> |



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

AI가 탐지한 위협(Threat) 정보는 Solidity 기반 `ThreatRegistry` Smart Contract에 등록됩니다.

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
| :--- | :--- |
| **Frontend** | ![React](https://img.shields.io/badge/React-61DAFB?style=flat-square&logo=react&logoColor=black) ![Vite](https://img.shields.io/badge/Vite-646CFF?style=flat-square&logo=vite&logoColor=white) ![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white) |
| **Backend** | ![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white) ![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) |
| **Dynamic Analysis** | ![Playwright](https://img.shields.io/badge/Playwright-2EAD33?style=flat-square&logo=playwright&logoColor=white) |
| **AI** | ![Google Gemini](https://img.shields.io/badge/Google_Gemini-8E75B2?style=flat-square&logo=googlegemini&logoColor=white) |
| **Smart Contract** | ![Solidity](https://img.shields.io/badge/Solidity-363636?style=flat-square&logo=solidity&logoColor=white) |
| **Blockchain** | ![Hardhat](https://img.shields.io/badge/Hardhat-FFF100?style=flat-square&logo=hardhat&logoColor=black) |
| **Web3 Integration** | ![Ethers.js](https://img.shields.io/badge/Ethers.js-24292E?style=flat-square&logo=ethereum&logoColor=white) |
| **Realtime** | ![WebSocket](https://img.shields.io/badge/WebSocket-010101?style=flat-square&logo=socketdotio&logoColor=white) ![Event Listener](https://img.shields.io/badge/Event_Listener-4A4A4A?style=flat-square) |

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

## 7. Getting Started

### 7.1 Environment Variables (.env)

`backend` 폴더 내에 `.env` 파일을 생성하고 본인의 Google Gemini API Key를 입력합니다.

| 파일 위치 | 환경변수명 | 설명 |
| :--- | :--- | :--- |
| `backend/.env` | `GEMINI_API_KEY` | Gemini API 분석 엔진에 필요한 인증 키 (`GEMINI_API_KEY=your_key_here`) |



### 7.2 Installation & Setup

| 구분 | 실행 경로 | 실행 명령어 | 역할 및 설명 |
| :--- | :--- | :--- | :--- |
| **백엔드/Playwright 설치** | `backend` | `pip install playwright --break-system-packages`<br>`python -m playwright install chromium` | 파이썬 의존성 패키지 및 샌드박스 동적 분석용 Chromium 브라우저 설치 |
| **프론트엔드 설치** | `frontend` | `npm install` | React UI 관련 패키지 설치 |



### 7.3 Execution Steps

각 서버 구동을 위해 3개의 터미널을 열어 아래 명령어를 각각 실행합니다.

| 구분 | 실행 경로 | 실행 명령어 | 역할 및 설명 |
| :--- | :--- | :--- | :--- |
| **Backend Server (터미널 1)** | `backend` | `python -m uvicorn main:app --port 8000` | FastAPI 메인 서버 및 AI 분석 엔진 실행 |
| **Frontend Server (터미널 2)** | `frontend` | `npm run dev` | 웹 대시보드 UI 실행 |
| **Test Target Server (터미널 3)** | `backend` | `python test_target_server.py` | Playwright 동적 분석을 위한 모의 피싱 타겟 서버 실행 |

---

## 8. Blockchain Demo

SafeShield의 Blockchain Demo는 **3개의 Terminal**을 사용하여 Local Blockchain, Validator 검증, Event 감지를 동시에 실행합니다.

https://github.com/user-attachments/assets/9f503fcf-c2f3-4b15-84c1-57ee03a9864a


## 9. Blockchain System Execution & Verification

SafeShield의 Blockchain Demo는 **3개의 Terminal**을 사용하여 Local Blockchain, Validator 검증, Event 감지를 동시에 실행합니다.

<!-- Blockchain_Demo.mp4 영상 -->

### 9.1 Demo Structure

| Terminal | 역할 | 실행 내용 |
| :--- | :--- | :--- |
| **Terminal 1** | Local Blockchain | Hardhat Local Network 실행 |
| **Terminal 2** | Deploy / Submit / Vote | Contract 배포 → Threat 등록 → Validator 투표 |
| **Terminal 3** | Event Listener | `ThreatConfirmed` 이벤트 실시간 감지 |

### 9.2 Execution

**Terminal 1 — Local Blockchain**

```bash
npx hardhat node
```

**Terminal 2 — Deploy & Submit**

```bash
node scripts/deployThreatRegistry.js
node scripts/submitThreat.js http://malicious-example.com/test
```

Contract 배포 시 Validator Account를 선택하며, Validator 수에 따라 **과반수 Threshold**가 자동 계산됩니다.  
Threat 등록 후 출력되는 `Threat ID`를 사용하여 Validator 투표를 진행합니다.

**Terminal 3 — Event Listener**

```bash
node scripts/listener.js
```

**Terminal 2 — Validator Vote**

```bash
node scripts/approveThreat.js <THREAT_ID>
```

각 Validator는 `APPROVE(악성)` 또는 `REJECT(정상)` 중 하나를 선택합니다.

### 9.3 Validation Result

| 조건 | 최종 상태 | Blacklist |
| :--- | :--- | :--- |
| APPROVE ≥ Threshold | `CONFIRMED` | `true` |
| REJECT ≥ Threshold | `REJECTED` | `false` |
| Threshold 미도달 | `PENDING` | `false` |

과반수 Validator가 `APPROVE`하면 다음과 같이 상태가 변경됩니다.

```text
Status: CONFIRMED
Blacklisted: true
```

동시에 `ThreatConfirmed` 이벤트가 발생하며 Terminal 3의 Event Listener에서 확인할 수 있습니다.

### 9.4 Test

Smart Contract의 Threat 등록, Validator 검증, 상태 변경 등의 핵심 로직을 테스트합니다.

```bash
npx hardhat test
```



