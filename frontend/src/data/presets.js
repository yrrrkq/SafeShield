export const ATTACK_PRESETS = [
  {
    id: "cj-delivery",
    category: "Smishing (Parcel Scam)",
    title: "[CJ대한통운] 도로명 주소 불일치 배송 보류 안내",
    senderNumber: "1588-1255",
    timestamp: "방금 전",
    smsText: "[CJ대한통운] 고객님의 운송장(6820-****) 도로명 주소 불일치로 배송이 보류되었습니다. 즉시 주소 확인 및 앱 업데이트 후 배송 재개 요청 바랍니다. http://fake-cj-delivery-check.com/track.apk",
    url: "http://fake-cj-delivery-check.com/track.apk",
    threatType: "CJ Parcel Smishing (Trojan.Dropper)",
    severity: "HIGH",
    expectedRiskScore: 94,
    description: "택배 배송 조회를 위장하여 악성 APK를 자동 다운로드하게 유도하고, SMS 인증번호 탈취 및 권한 탈취를 시도합니다.",
    icon: "📦",
    samplePermissions: [
      "android.permission.READ_SMS",
      "android.permission.RECEIVE_SMS",
      "android.permission.SEND_SMS",
      "android.permission.READ_CONTACTS",
      "android.permission.SYSTEM_ALERT_WINDOW"
    ]
  },
  {
    id: "wedding-card",
    category: "Smishing (Wedding Invitation)",
    title: "[모바일 청첩장] 김민준 ❤️ 이서연 결혼식에 초대합니다",
    senderNumber: "010-4821-9923",
    timestamp: "12분 전",
    smsText: "[모바일청첩장] 저희 두 사람의 소중한 시작을 함께 축복해 주세요. 모바일 청첩장 보기 및 모바일 식권 다운로드: http://mobile-wedding-card-view.net/invitation.apk",
    url: "http://mobile-wedding-card-view.net/invitation.apk",
    threatType: "Mobile Wedding Invitation Smishing (Trojan.Spy)",
    severity: "CRITICAL",
    expectedRiskScore: 96,
    description: "지인을 사칭한 모바일 청첩장 링크를 통해 스파이웨어를 설치하고, 주소록 전송 및 소액결제 OTP를 가로챕니다.",
    icon: "💌",
    samplePermissions: [
      "android.permission.READ_SMS",
      "android.permission.RECEIVE_SMS",
      "android.permission.READ_CONTACTS",
      "android.permission.RECORD_AUDIO",
      "android.permission.SEND_SMS"
    ]
  },
  {
    id: "gov-loan",
    category: "Voice Phishing (Gov Support Loan)",
    title: "[정부지원] 2026 긴급 서민 금융 대환대출 신청 안내",
    senderNumber: "1397",
    timestamp: "1시간 전",
    smsText: "[서민금융진흥원] 귀하는 2026 정부 특별 저금리(연 2.1%) 대환대출 지원 대상자입니다. 한도 즉시 조회 및 전용 보안앱 설치: http://gov-support-loan-center.org/app.apk",
    url: "http://gov-support-loan-center.org/app.apk",
    threatType: "Emergency Loan / Gov Grant Phishing (Trojan.Banker)",
    severity: "CRITICAL",
    expectedRiskScore: 97,
    description: "저금리 대환 대출을 미끼로 가짜 금융사 앱을 설치시키고, 금융 앱 실행 시 화면을 가로채는 피싱 오버레이를 띄웁니다.",
    icon: "🏦",
    samplePermissions: [
      "android.permission.BIND_ACCESSIBILITY_SERVICE",
      "android.permission.SYSTEM_ALERT_WINDOW",
      "android.permission.QUERY_ALL_PACKAGES",
      "android.permission.CALL_PHONE",
      "android.permission.READ_SMS"
    ]
  },
  {
    id: "police-wiretap",
    category: "Voice Phishing (Fake Police App)",
    title: "[경찰청/검찰청] 금융사기 사건 연루 확인 및 안심보안앱",
    senderNumber: "02-3150-2112",
    timestamp: "어제",
    smsText: "[경찰청 사이버수사국] 귀하의 명의가 대포통장 범죄에 연루되었습니다. 자산 동결 방지를 위해 즉시 경찰 공용 안심 보안인증앱을 설치하십시오: http://police-cyber-security-kr.cc/protect.apk",
    url: "http://police-cyber-security-kr.cc/protect.apk",
    threatType: "Fake Police / Prosecutor Wiretap App (Trojan.Spy.CallHijack)",
    severity: "CRITICAL",
    expectedRiskScore: 99,
    description: "피해자가 112나 금감원에 신고 전화를 걸면 악성 앱이 통화를 가로채 사기범 콜센터로 강제 연결(전화 가로채기)합니다.",
    icon: "🚨",
    samplePermissions: [
      "android.permission.BIND_ACCESSIBILITY_SERVICE",
      "android.permission.CALL_PHONE",
      "android.permission.RECORD_AUDIO",
      "android.permission.READ_SMS",
      "android.permission.RECEIVE_SMS",
      "android.permission.SYSTEM_ALERT_WINDOW",
      "android.permission.QUERY_ALL_PACKAGES"
    ]
  }
];

export const INITIAL_NODES = [
  {
    id: "node-kisa",
    name: "KISA (Korea Internet & Security Agency)",
    shortName: "KISA CERT",
    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    type: "National CERT",
    status: "ONLINE",
    reputation: 99.8,
    avatar: "🛡️",
    isPrimaryProposer: true
  },
  {
    id: "node-ahnlab",
    name: "AhnLab Cyber Threat Intelligence",
    shortName: "AhnLab ASEC",
    address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    type: "Commercial Anti-Virus",
    status: "ONLINE",
    reputation: 99.4,
    avatar: "🔬",
    isPrimaryProposer: false
  },
  {
    id: "node-police",
    name: "National Police Agency Cyber Bureau",
    shortName: "KNPA Cyber",
    address: "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    type: "Law Enforcement",
    status: "ONLINE",
    reputation: 98.9,
    avatar: "🚨",
    isPrimaryProposer: false
  },
  {
    id: "node-fss",
    name: "FSS Financial Anti-Phishing Center",
    shortName: "FSS PhishStop",
    address: "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
    type: "Financial Regulator",
    status: "ONLINE",
    reputation: 99.1,
    avatar: "🏦",
    isPrimaryProposer: false
  }
];
