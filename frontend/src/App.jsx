import React, { useState, useEffect, useCallback } from 'react';
import { OnChainDashboard } from './components/OnChainDashboard';
import { ThreatDetailModal } from './components/ThreatDetailModal';
import { MultiSigConsensusBar } from './components/MultiSigConsensusBar';
import { AntiTransferLockerPage } from './components/AntiTransferLockerPage';
import { ATTACK_PRESETS, INITIAL_NODES } from './data/presets';
import { localBlockchain } from './services/mockBlockchain';
import {
  checkBackendHealth,
  analyzeUrl,
  fetchMockBankAccount,
  attemptMockTransfer,
  lockMockAccount,
  unlockMockAccount
} from './services/api';

// Demo virtual account identifiers (mock_bank.py) — NOT real bank accounts.
const DEMO_VICTIM_ACCOUNT = 'demo-victim-001';
const DEMO_SCAM_ACCOUNT = 'demo-attacker-999';

// -----------------------------------------------------------------------
// Client-side metadata used only to render human-readable permission
// labels for the permission *names* the backend actually detected
// (data.detected_permissions is a plain list of strings like "READ_SMS").
// -----------------------------------------------------------------------
const PERMISSION_META = {
  BIND_ACCESSIBILITY_SERVICE: { name: '접근성 서비스 탈취', danger: 'CRITICAL', description: '화면 내용을 읽고 버튼을 자동으로 눌러 금융 정보를 탈취할 수 있습니다.' },
  SYSTEM_ALERT_WINDOW: { name: '오버레이 삽입 (가짜 뱅킹 UI)', danger: 'CRITICAL', description: '정상 뱅킹 앱 위에 가짜 화면을 띄워 비밀번호를 가로챕니다.' },
  READ_SMS: { name: 'SMS 읽기 & OTP 탈취', danger: 'HIGH', description: '수신 문자에서 2차 인증(OTP) 코드를 탈취합니다.' },
  RECEIVE_SMS: { name: 'SMS 수신 감청', danger: 'HIGH', description: '은행 알림 문자를 가로채 사용자 몰래 삭제합니다.' },
  SEND_SMS: { name: '문자 스팸 발송', danger: 'HIGH', description: '연락처 전체에 스미싱 문자를 대량 발송합니다.' },
  CALL_PHONE: { name: '전화 가로채기/리다이렉트', danger: 'HIGH', description: '금융감독원/경찰 통화를 가로채 사기범 콜센터로 연결합니다.' },
  RECORD_AUDIO: { name: '마이크 도청', danger: 'HIGH', description: '실시간으로 통화 및 주변 음성을 녹음합니다.' },
  READ_CONTACTS: { name: '연락처 탈취', danger: 'MEDIUM', description: '가족/지인 연락처를 유출해 2차 피해를 유발합니다.' },
  QUERY_ALL_PACKAGES: { name: '설치 앱 스캔', danger: 'MEDIUM', description: '설치된 은행/보안 앱을 스캔해 표적 오버레이를 배치합니다.' },
  RECEIVE_BOOT_COMPLETED: { name: '재부팅 시 자동 실행', danger: 'LOW', description: '기기가 재부팅되어도 자동으로 다시 실행됩니다.' }
};

function buildPermissionDetails(detectedPermissions) {
  if (!Array.isArray(detectedPermissions) || detectedPermissions.length === 0) return [];
  return detectedPermissions.map((perm) => {
    const meta = PERMISSION_META[perm] || { name: perm, danger: 'MEDIUM', description: '위험 권한이 감지되었습니다.' };
    return { permission: perm, ...meta };
  });
}

/**
 * Normalizes the raw /api/sandbox/analyze response into the shape the UI
 * renders. Every field here traces back to something the backend actually
 * observed — nothing is invented, and absent data (no APK, no permissions,
 * not locked, no AI classifier) is passed through as explicit
 * empty/false/null values rather than being backfilled with demo data.
 */
function normalizeAnalysis(apiResult) {
  const ai = apiResult.ai_analysis || {};
  const matchedKeywords = ai.matched_keywords || [];
  const reachable = !!apiResult.reachable;
  const aiClassifier = ai.ai_classifier || { used: false };

  const threatType = !reachable
    ? '접속 불가 / 분석 불가'
    : matchedKeywords.length > 0
      ? `스미싱 의심 문맥 탐지 (${matchedKeywords.join(', ')})`
      : '특이 스미싱 문맥 없음';

  return {
    reachable,
    errorDetail: apiResult.error_detail || apiResult.error || null,
    riskScore: typeof ai.threat_score === 'number' ? ai.threat_score : 0,
    verdict: ai.verdict || 'UNKNOWN',
    confidenceLevel: ai.confidence_level || 'N/A',
    breakdown: ai.breakdown || { dynamic_behavior_score: 0, static_permission_score: 0, nlp_context_score: 0 },
    threatType,
    permissions: buildPermissionDetails(apiResult.detected_permissions),
    sha256: apiResult.apk_hash || null,
    apkDownloaded: !!apiResult.apk_downloaded,
    url: apiResult.url,
    redirectChain: ai.redirect_chain || [],
    matchedKeywords,
    locked: !!(apiResult.b2c_actions && apiResult.b2c_actions.anti_transfer_lock && apiResult.b2c_actions.anti_transfer_lock.locked),
    justLocked: !!(apiResult.b2c_actions && apiResult.b2c_actions.anti_transfer_lock && apiResult.b2c_actions.anti_transfer_lock.justLocked),
    lockMessage: (apiResult.b2c_actions && apiResult.b2c_actions.anti_transfer_lock && apiResult.b2c_actions.anti_transfer_lock.message) || '',
    demoAccount: (apiResult.b2c_actions && apiResult.b2c_actions.anti_transfer_lock && apiResult.b2c_actions.anti_transfer_lock.demoAccount) || null,
    // Genuine info about whether Gemini (LLM) actually produced a full
    // threat ANALYSIS (not just a label), or whether it fell back to
    // keyword counting — never fabricated.
    aiClassifier: {
      used: !!aiClassifier.used,
      reasoning: aiClassifier.reasoning || null,
      confidence: aiClassifier.confidence ?? null,
      model: aiClassifier.model || null,
      isPhishing: aiClassifier.isPhishing ?? null,
      phishingCategory: aiClassifier.phishingCategory || null,
      impersonatedEntity: aiClassifier.impersonatedEntity || null,
      socialEngineeringTactics: aiClassifier.socialEngineeringTactics || [],
      technicalCorrelation: aiClassifier.technicalCorrelation || null,
      recommendedAction: aiClassifier.recommendedAction || null
    }
  };
}

function riskLevelFromScore(score) {
  if (score >= 80) return '높음';
  if (score >= 40) return '보통';
  return '낮음';
}

function RiskBadge({ level }) {
  const styles = {
    '높음': 'bg-red-50 text-red-600 border-red-200',
    '보통': 'bg-orange-50 text-orange-600 border-orange-200',
    '낮음': 'bg-emerald-50 text-emerald-600 border-emerald-200'
  };
  return (
    <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border shrink-0 ${styles[level] || styles['낮음']}`}>
      위험도 {level}
    </span>
  );
}

/**
 * Builds the real, data-driven bullet points for "AI 판단 근거" — every
 * line here is conditioned on something the backend actually detected.
 * When nothing was detected, it says so plainly instead of inventing a
 * generic-sounding justification.
 */
function buildAiReasoningBullets(analysis) {
  if (!analysis || !analysis.reachable) return [];
  const bullets = [];

  if (analysis.aiClassifier.used) {
    if (analysis.aiClassifier.impersonatedEntity) {
      bullets.push(`(AI 분석) 사칭 대상으로 추정되는 기관/인물: ${analysis.aiClassifier.impersonatedEntity}`);
    }
    if (analysis.aiClassifier.socialEngineeringTactics.length > 0) {
      bullets.push(`(AI 분석) 사용된 사회공학 기법: ${analysis.aiClassifier.socialEngineeringTactics.join(', ')}`);
    }
    if (analysis.aiClassifier.technicalCorrelation) {
      bullets.push(`(AI 분석) 텍스트-기술적 증거 상관관계: ${analysis.aiClassifier.technicalCorrelation}`);
    }
    if (analysis.aiClassifier.reasoning) {
      bullets.push(`(AI 종합 판단, 확신도 ${analysis.aiClassifier.confidence ?? '-'}%) ${analysis.aiClassifier.reasoning}`);
    }
  }
  if (analysis.matchedKeywords.length > 0) {
    bullets.push(`(키워드 매칭) 본문에서 스미싱 의심 키워드 발견: ${analysis.matchedKeywords.join(', ')}`);
  }
  if (analysis.redirectChain.length > 0) {
    bullets.push(`실제 접속 시 ${analysis.redirectChain.length}건의 HTTP 리다이렉트가 관찰됨`);
  }
  if (analysis.apkDownloaded && analysis.permissions.length > 0) {
    bullets.push(
      `다운로드된 APK에서 위험 권한 ${analysis.permissions.length}개 탐지: ${analysis.permissions.map(p => p.name).join(', ')}`
    );
  } else if (analysis.apkDownloaded) {
    bullets.push('APK 파일이 다운로드되었으나 위험 권한은 발견되지 않음');
  }
  if (bullets.length === 0) {
    bullets.push('특이 위협 신호가 탐지되지 않았습니다 (리다이렉트/APK 다운로드/의심 키워드 없음)');
  }
  return bullets;
}

// =====================================================================
// Sidebar
// =====================================================================
function Sidebar({ activeTab, setActiveTab }) {
  const navItems = [
    { id: 'sandbox', icon: '⟨⟩', label: '실시간 분석' },
    { id: 'transfer-lock', icon: '🔒', label: '송금 일시정지 막기' },
    { id: 'onchain-ledger', icon: '⛓️', label: 'Web3 온체인 원장' },
    { id: 'settings', icon: '⚙️', label: '설정' }
  ];
  return (
    <aside className="w-60 shrink-0 bg-[#0f1729] text-slate-300 flex flex-col">
      <div className="flex items-center gap-2 px-5 py-5 border-b border-slate-800">
        <span className="text-2xl">🛡️</span>
        <span className="text-white font-bold text-lg">SafeShield</span>
      </div>
      <nav className="flex-1 py-4 px-3 space-y-1">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
              activeTab === item.id
                ? 'bg-blue-600 text-white'
                : 'text-slate-300 hover:bg-slate-800 hover:text-white'
            }`}
          >
            <span>{item.icon}</span>
            <span>{item.label}</span>
          </button>
        ))}
      </nav>
    </aside>
  );
}

// =====================================================================
// Top header
// =====================================================================
function TopHeader({ isBackendOnline }) {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 30000);
    return () => clearInterval(t);
  }, []);
  const dateLabel = now.toLocaleDateString('ko-KR') + ' ' + now.toTimeString().slice(0, 5);

  return (
    <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-6 shrink-0">
      <div>
        <h1 className="text-base font-bold text-slate-900">SafeShield</h1>
        <p className="text-xs text-slate-500">AI 기반 스미싱・보이스피싱 탐지 및 실시간 차단 시스템</p>
      </div>
      <div className="flex items-center gap-3">
        <span
          className={`flex items-center gap-1.5 text-xs font-medium px-3 py-1 rounded-full border ${
            isBackendOnline ? 'bg-emerald-50 text-emerald-600 border-emerald-200' : 'bg-red-50 text-red-600 border-red-200'
          }`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${isBackendOnline ? 'bg-emerald-500' : 'bg-red-500'}`} />
          {isBackendOnline ? '백엔드 연결됨' : '백엔드 연결 안 됨'}
        </span>
        <span className="text-xs text-slate-400">{dateLabel}</span>
        <div className="w-8 h-8 rounded-full bg-slate-800 text-white text-xs font-semibold flex items-center justify-center">
          YS
        </div>
      </div>
    </header>
  );
}

// =====================================================================
// Step breadcrumb
// =====================================================================
function StepBreadcrumb({ activeTab, setActiveTab }) {
  const steps = [
    { id: 'sandbox', num: 1, label: '스미싱/악성코드 실시간 분석' },
    { id: 'transfer-lock', num: 2, label: '송금 일시정지 막기' },
    { id: 'onchain-ledger', num: 3, label: 'Web3 온체인 원장' }
  ];
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
      {steps.map((s, i) => (
        <React.Fragment key={s.id}>
          <button
            onClick={() => setActiveTab(s.id)}
            className={`flex items-center gap-1.5 px-1.5 py-1 rounded-full ${
              activeTab === s.id ? 'text-blue-600 font-semibold' : 'text-slate-400 hover:text-slate-600'
            }`}
          >
            <span
              className={`w-4 h-4 rounded-full flex items-center justify-center text-[10px] ${
                activeTab === s.id ? 'bg-blue-600 text-white' : 'bg-slate-200 text-slate-500'
              }`}
            >
              {s.num}
            </span>
            {s.label}
          </button>
          {i < steps.length - 1 && <span className="text-slate-300">—</span>}
        </React.Fragment>
      ))}
    </div>
  );
}

// =====================================================================
// Left column: scenario selector + phone mock + custom input
// =====================================================================
function ScenarioPanel({
  selectedPreset,
  onSelectPreset,
  customUrl,
  setCustomUrl,
  customText,
  setCustomText,
  onTriggerAttack,
  isAnalyzing
}) {
  const [showCustom, setShowCustom] = useState(true);
  const displaySms = customText || selectedPreset.smsText || '';

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
      <h2 className="text-sm font-bold text-slate-900">시나리오 선택</h2>

      <div className="space-y-2">
        {ATTACK_PRESETS.map((preset) => {
          const active = !customUrl && !customText && selectedPreset.id === preset.id;
          return (
            <button
              key={preset.id}
              onClick={() => onSelectPreset(preset)}
              className={`w-full flex items-center gap-3 text-left px-3 py-2.5 rounded-lg border transition ${
                active ? 'border-blue-500 bg-blue-50' : 'border-slate-200 hover:border-slate-300'
              }`}
            >
              <span className="text-lg">📩</span>
              <span className="flex-1 min-w-0">
                <span className="block text-sm font-medium text-slate-800 truncate">{preset.title || preset.threatType}</span>
                <span className="block text-[11px] text-slate-400 truncate">{preset.category || preset.url}</span>
              </span>
              <span className="text-slate-300">›</span>
            </button>
          );
        })}
      </div>

      <div className="border-t border-slate-200 pt-3">
        <button
          onClick={() => setShowCustom((v) => !v)}
          className="text-xs text-blue-600 font-medium"
        >
          {showCustom ? '직접 입력 숨기기' : '직접 입력 (Custom)'}
        </button>
        {showCustom && (
          <div className="mt-2 space-y-2">
            <div>
              <label className="block text-[11px] text-slate-500 mb-1">Custom SMS Text</label>
              <input
                type="text"
                value={customText}
                onChange={(e) => setCustomText(e.target.value)}
                placeholder="[택배] 배송지 주소 불일치 확인..."
                className="w-full text-xs border border-slate-300 rounded-lg px-2.5 py-2 text-slate-700"
              />
            </div>
            <div>
              <label className="block text-[11px] text-slate-500 mb-1">Malicious URL</label>
              <input
                type="text"
                value={customUrl}
                onChange={(e) => setCustomUrl(e.target.value)}
                placeholder="http://127.0.0.1:9100/police"
                className="w-full text-xs border border-slate-300 rounded-lg px-2.5 py-2 text-slate-700 font-mono"
              />
            </div>
          </div>
        )}
      </div>

      {/* Phone mockup */}
      <div className="mx-auto w-full max-w-[260px] bg-slate-900 rounded-[28px] p-3 shadow-lg">
        <div className="bg-white rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between px-3 py-1.5 text-[10px] text-slate-500 bg-slate-50">
            <span>12:45</span>
            <span>📶 📡 🔋</span>
          </div>
          <div className="p-3 space-y-2">
            <div className="text-[11px] text-slate-400">Unknown Sender</div>
            <div className="bg-slate-100 rounded-xl rounded-tl-sm px-3 py-2 text-[11px] text-slate-700 leading-relaxed break-words">
              {displaySms || '메시지를 선택하거나 직접 입력해주세요.'}
            </div>
          </div>
        </div>
      </div>

      <button
        onClick={onTriggerAttack}
        disabled={isAnalyzing}
        className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-semibold"
      >
        {isAnalyzing ? '분석 중...' : '🔍 실시간 분석 실행'}
      </button>
    </div>
  );
}

// =====================================================================
// Right column: AI 분석 결과 (result table)
// =====================================================================
function AnalysisResultPanel({ analysis, isAnalyzing, analysisTimestamp, logs, setActiveTab }) {
  const [showLogs, setShowLogs] = useState(false);

  if (isAnalyzing) {
    return (
      <div className="bg-white rounded-xl border border-slate-200 p-8 flex flex-col items-center justify-center gap-3 text-slate-500 text-sm animate-pulse">
        <span className="text-2xl">🔍</span>
        실시간으로 URL에 접속하여 분석 중입니다...
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="bg-white rounded-xl border border-slate-200 p-8 flex flex-col items-center justify-center gap-2 text-slate-400 text-sm">
        <span className="text-2xl">🛡️</span>
        시나리오를 선택하고 "실시간 분석 실행"을 눌러주세요.
      </div>
    );
  }

  const bullets = buildAiReasoningBullets(analysis);
  const overallLevel = !analysis.reachable ? null : riskLevelFromScore(analysis.riskScore);

  return (
    <div className="space-y-4">
      {/* Risk banner */}
      {!analysis.reachable ? (
        <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 flex items-start justify-between gap-3">
          <div>
            <div className="text-amber-700 font-bold text-sm flex items-center gap-2">⚠️ 대상에 접속할 수 없습니다</div>
            <p className="text-amber-700/80 text-xs mt-1">{analysis.errorDetail || '도메인 접속 불가 / 존재하지 않는 URL'}</p>
          </div>
        </div>
      ) : (
        <div
          className={`rounded-xl border p-4 flex items-start justify-between gap-3 ${
            overallLevel === '높음'
              ? 'border-red-200 bg-red-50'
              : overallLevel === '보통'
                ? 'border-orange-200 bg-orange-50'
                : 'border-emerald-200 bg-emerald-50'
          }`}
        >
          <div>
            <div
              className={`font-bold text-sm flex items-center gap-2 ${
                overallLevel === '높음' ? 'text-red-700' : overallLevel === '보통' ? 'text-orange-700' : 'text-emerald-700'
              }`}
            >
              🛡️ 위험도 {overallLevel} · {analysis.riskScore}/100 ({analysis.verdict})
            </div>
            <p className="text-xs mt-1 opacity-80">
              {overallLevel === '높음'
                ? '스미싱/악성코드로 의심되는 대상입니다. 즉시 주의가 필요합니다.'
                : overallLevel === '보통'
                  ? '일부 의심 신호가 발견되었습니다.'
                  : '특이 위협 신호가 발견되지 않았습니다.'}
            </p>
          </div>
          {analysis.locked && (
            <span className="shrink-0 text-[11px] font-semibold px-3 py-1 rounded-full bg-white border border-red-300 text-red-600">
              ✓ 차단 완료
            </span>
          )}
        </div>
      )}

      {/* AI 위협 분석 리포트 — only rendered when Gemini actually produced a
          real analysis (not the keyword fallback). Every field here is the
          model's own output for THIS request, not a template. */}
      {analysis.reachable && analysis.aiClassifier.used && (
        <div className="bg-white rounded-xl border border-indigo-200 overflow-hidden">
          <div className="bg-indigo-50 px-5 py-3 border-b border-indigo-100 flex items-center justify-between">
            <h3 className="text-sm font-bold text-indigo-900 flex items-center gap-2">
              🤖 AI 위협 분석 리포트
            </h3>
            <span className="text-[11px] text-indigo-500">
              {analysis.aiClassifier.model} · 확신도 {analysis.aiClassifier.confidence}%
            </span>
          </div>
          <div className="px-5 py-4 space-y-3 text-sm">
            <div className="flex flex-wrap gap-2">
              <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-indigo-100 text-indigo-700">
                {analysis.aiClassifier.phishingCategory || '분류 미상'}
              </span>
              {analysis.aiClassifier.impersonatedEntity && (
                <span className="text-xs px-2.5 py-1 rounded-full bg-slate-100 text-slate-600">
                  사칭 대상: {analysis.aiClassifier.impersonatedEntity}
                </span>
              )}
            </div>

            {analysis.aiClassifier.socialEngineeringTactics.length > 0 && (
              <div>
                <div className="text-xs font-medium text-slate-400 mb-1">사용된 사회공학 기법</div>
                <div className="flex flex-wrap gap-1.5">
                  {analysis.aiClassifier.socialEngineeringTactics.map((t, i) => (
                    <span key={i} className="text-[11px] px-2 py-0.5 rounded-full border border-amber-200 bg-amber-50 text-amber-700">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {analysis.aiClassifier.technicalCorrelation && (
              <div>
                <div className="text-xs font-medium text-slate-400 mb-1">텍스트 ↔ 실제 기술적 증거 상관관계</div>
                <p className="text-xs text-slate-600">{analysis.aiClassifier.technicalCorrelation}</p>
              </div>
            )}

            <div>
              <div className="text-xs font-medium text-slate-400 mb-1">종합 분석</div>
              <p className="text-xs text-slate-600 leading-relaxed">{analysis.aiClassifier.reasoning}</p>
            </div>

            {analysis.aiClassifier.recommendedAction && (
              <div className="bg-indigo-50 rounded-lg px-3 py-2">
                <span className="text-xs font-semibold text-indigo-700">권고 조치: </span>
                <span className="text-xs text-indigo-700">{analysis.aiClassifier.recommendedAction}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Result table */}
      <div className="bg-white rounded-xl border border-slate-200 divide-y divide-slate-100">
        <div className="px-5 py-3">
          <h3 className="text-sm font-bold text-slate-900">AI 분석 결과</h3>
        </div>

        <ResultRow icon="📍" label="분석 대상 URL">
          <span className="font-mono text-xs break-all">{analysis.url}</span>
          {analysis.reachable && <RiskBadge level={overallLevel} />}
        </ResultRow>

        <ResultRow icon="✉️" label="메시지 내용">
          <span className="text-xs text-slate-600 break-words">{analysis.threatType}</span>
        </ResultRow>

        <ResultRow icon="🔗" label="URL 분석">
          <span className="text-xs text-slate-600">
            {analysis.reachable
              ? `실제 접속 성공 · 리다이렉트 ${analysis.redirectChain.length}건`
              : '접속 실패 (분석 불가)'}
          </span>
          {analysis.reachable && <RiskBadge level={overallLevel} />}
        </ResultRow>

        <ResultRow icon="📄" label="파일 유형">
          <span className="text-xs text-slate-600">
            {analysis.apkDownloaded ? `APK 파일 (실제 다운로드됨, SHA-256: ${analysis.sha256 ? analysis.sha256.slice(0, 18) + '...' : '-'})` : '다운로드된 파일 없음'}
          </span>
          {analysis.apkDownloaded && <RiskBadge level={analysis.breakdown.static_permission_score > 0 ? '높음' : '낮음'} />}
        </ResultRow>

        <ResultRow icon="🤖" label="AI 판단 근거">
          <ul className="text-xs text-slate-600 space-y-1 list-disc list-inside">
            {bullets.map((b, i) => (
              <li key={i}>{b}</li>
            ))}
          </ul>
        </ResultRow>
      </div>

      {/* 대응 조치 */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex items-center justify-between gap-3">
        <div>
          <div className="text-blue-700 font-bold text-sm flex items-center gap-2">🛡️ 대응 조치</div>
          <p className="text-xs text-blue-700/80 mt-1">
            {analysis.locked
              ? '사용자에게 위험을 알리고, 데모 가상계좌의 송금을 30분간 일시 정지했습니다.'
              : '위험 점수가 안전 기준 내에 있어 별도 조치 없이 금융 이체가 허용됩니다.'}
          </p>
        </div>
        <button
          onClick={() => setActiveTab('transfer-lock')}
          className="shrink-0 text-xs font-semibold text-blue-700 border border-blue-300 bg-white rounded-lg px-3 py-1.5 hover:bg-blue-100"
        >
          상세 분석 보기 →
        </button>
      </div>

      {/* Bottom info bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
        <InfoTile icon="🕐" label="분석 시간" value={analysisTimestamp || '-'} />
        <InfoTile
          icon="⏱️"
          label="분석 모델"
          value={analysis.aiClassifier.used ? `Gemini AI (${analysis.aiClassifier.model})` : 'SafeShield Heuristic v1 (키워드 기반)'}
        />
        <InfoTile
          icon="📎"
          label="추가 탐지 항목"
          value={
            [
              analysis.breakdown.dynamic_behavior_score > 0 && '동적 행위',
              analysis.breakdown.static_permission_score > 0 && '위험 권한',
              analysis.breakdown.nlp_context_score > 0 && (analysis.aiClassifier.used ? 'AI 문맥 분석' : '키워드 문맥'),
            ]
              .filter(Boolean)
              .join(', ') || '없음'
          }
        />
      </div>

      {/* Real step-by-step log, collapsible */}
      {logs.length > 0 && (
        <div className="bg-white rounded-xl border border-slate-200">
          <button
            onClick={() => setShowLogs((v) => !v)}
            className="w-full flex items-center justify-between px-5 py-3 text-xs font-semibold text-slate-600"
          >
            <span>🔍 상세 분석 로그 보기 ({logs.length}개 이벤트)</span>
            <span>{showLogs ? '▲' : '▼'}</span>
          </button>
          {showLogs && (
            <div className="px-5 pb-4 space-y-1 max-h-64 overflow-y-auto font-mono text-[11px]">
              {logs.map((log, i) => (
                <div key={i} className="text-slate-500">
                  <span className="text-slate-400">{log.timestamp}</span>{' '}
                  <span className="text-slate-400">[{log.level}]</span> {log.message}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ResultRow({ icon, label, children }) {
  return (
    <div className="px-5 py-3 flex items-start gap-4">
      <div className="w-28 shrink-0 flex items-center gap-2 text-xs font-medium text-slate-500 pt-0.5">
        <span>{icon}</span>
        {label}
      </div>
      <div className="flex-1 flex items-center flex-wrap gap-2">{children}</div>
    </div>
  );
}

function InfoTile({ icon, label, value }) {
  return (
    <div className="bg-white rounded-xl border border-slate-200 px-4 py-3 flex items-center gap-3">
      <span className="text-base">{icon}</span>
      <div className="min-w-0">
        <div className="text-slate-400">{label}</div>
        <div className="text-slate-700 font-medium truncate">{value}</div>
      </div>
    </div>
  );
}

// =====================================================================
// Mock Bank panel (used on the "송금 일시정지 막기" step)
// =====================================================================
function MockBankPanel({
  account,
  transferAmount,
  setTransferAmount,
  transferResult,
  isTransferring,
  onAttemptTransfer,
  onManualLock,
  onManualUnlock,
  isBankBusy
}) {
  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-3 text-sm">
      <div className="flex items-center justify-between">
        <span className="text-slate-900 font-bold">🏦 데모 가상계좌 (Mock Bank)</span>
        <span className="text-[10px] text-slate-400 border border-slate-200 rounded px-1.5 py-0.5">실제 은행 아님 · 데모 전용</span>
      </div>

      {!account ? (
        <div className="text-slate-400 text-xs">계좌 정보를 불러오는 중...</div>
      ) : (
        <>
          <div className="flex items-center justify-between">
            <span className="text-slate-500">{account.ownerName}</span>
            <span className="font-mono text-slate-800">{Number(account.balance).toLocaleString()} {account.currency}</span>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-slate-500">계좌 상태</span>
            {account.locked ? (
              <span className="px-2 py-0.5 rounded-full bg-red-50 border border-red-200 text-red-600 text-[11px] font-semibold">
                🔒 잠금 (약 {account.lockRemainingSeconds}초 남음)
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-600 text-[11px]">
                🔓 정상 (이체 가능)
              </span>
            )}
          </div>
          {account.locked && account.lockReason && (
            <div className="text-[11px] text-slate-400 break-words">사유: {account.lockReason}</div>
          )}

          <div className="border-t border-slate-100 pt-3 space-y-2">
            <div className="text-slate-500 text-xs">이 가상계좌 → 사기범 가상계좌로 송금 시도해보기</div>
            <div className="flex gap-2">
              <input
                type="number"
                min={1}
                value={transferAmount}
                onChange={(e) => setTransferAmount(e.target.value)}
                className="flex-1 bg-slate-50 border border-slate-200 rounded-lg px-2 py-1.5 text-slate-700 text-xs"
              />
              <button
                onClick={onAttemptTransfer}
                disabled={isTransferring}
                className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-xs font-medium text-white"
              >
                {isTransferring ? '전송 중...' : '송금 시도'}
              </button>
            </div>
          </div>

          {transferResult && (
            <div
              className={`rounded-lg p-2 text-[11px] border ${
                transferResult.success ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-red-200 bg-red-50 text-red-700'
              }`}
            >
              {transferResult.success ? '✅ ' : '⛔ '}
              {transferResult.message}
            </div>
          )}

          <div className="border-t border-slate-100 pt-3 flex gap-2">
            <button
              onClick={onManualLock}
              disabled={isBankBusy}
              className="flex-1 px-2 py-1.5 rounded-lg border border-slate-200 text-slate-500 text-[11px] hover:border-red-300 hover:text-red-600 disabled:opacity-50"
            >
              테스트: 강제 잠금
            </button>
            <button
              onClick={onManualUnlock}
              disabled={isBankBusy}
              className="flex-1 px-2 py-1.5 rounded-lg border border-slate-200 text-slate-500 text-[11px] hover:border-emerald-300 hover:text-emerald-600 disabled:opacity-50"
            >
              테스트: 강제 해제
            </button>
          </div>
        </>
      )}
    </div>
  );
}

// =====================================================================
// App
// =====================================================================
// =====================================================================
// Settings page — real, functional content only (backend/account status
// this app actually tracks), not placeholder text.
// =====================================================================
function SettingsPage({ isBackendOnline, mockAccount, onManualLock, onManualUnlock, isBankBusy }) {
  return (
    <div className="max-w-2xl space-y-5">
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
        <h2 className="text-sm font-bold text-slate-900">백엔드 연결 상태</h2>
        <div className="flex items-center justify-between text-sm">
          <span className="text-slate-500">FastAPI 백엔드 (localhost:8000)</span>
          <span
            className={`flex items-center gap-1.5 text-xs font-medium px-3 py-1 rounded-full border ${
              isBackendOnline ? 'bg-emerald-50 text-emerald-600 border-emerald-200' : 'bg-red-50 text-red-600 border-red-200'
            }`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${isBackendOnline ? 'bg-emerald-500' : 'bg-red-500'}`} />
            {isBackendOnline ? '연결됨' : '연결 안 됨'}
          </span>
        </div>
        {!isBackendOnline && (
          <p className="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded-lg p-2">
            백엔드가 꺼져 있으면 실시간 분석·송금 락·온체인 원장이 모두 동작하지 않습니다.
            터미널에서 <code className="font-mono">python -m uvicorn main:app --port 8000</code> 로 실행 중인지 확인해주세요.
          </p>
        )}
      </div>

      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
        <h2 className="text-sm font-bold text-slate-900">데모 가상계좌 (Mock Bank)</h2>
        {!mockAccount ? (
          <p className="text-xs text-slate-400">계좌 정보를 불러오는 중이거나 백엔드에 연결할 수 없습니다.</p>
        ) : (
          <>
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-500">{mockAccount.ownerName} ({mockAccount.accountNumber})</span>
              <span className="font-mono text-slate-800">{Number(mockAccount.balance).toLocaleString()} {mockAccount.currency}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-500">잠금 상태</span>
              {mockAccount.locked ? (
                <span className="px-2 py-0.5 rounded-full bg-red-50 border border-red-200 text-red-600 text-[11px] font-semibold">
                  🔒 잠금 (약 {mockAccount.lockRemainingSeconds}초 남음)
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-600 text-[11px]">
                  🔓 정상
                </span>
              )}
            </div>
            <div className="flex gap-2 pt-2">
              <button
                onClick={onManualLock}
                disabled={isBankBusy}
                className="flex-1 px-2 py-1.5 rounded-lg border border-slate-200 text-slate-500 text-xs hover:border-red-300 hover:text-red-600 disabled:opacity-50"
              >
                강제 잠금 (테스트)
              </button>
              <button
                onClick={onManualUnlock}
                disabled={isBankBusy}
                className="flex-1 px-2 py-1.5 rounded-lg border border-slate-200 text-slate-500 text-xs hover:border-emerald-300 hover:text-emerald-600 disabled:opacity-50"
              >
                즉시 잠금 해제
              </button>
            </div>
            <p className="text-[11px] text-slate-400">
              이 계좌는 실제 은행 계좌가 아니라, 데모용 가상 원장(mock_bank.py)입니다.
            </p>
          </>
        )}
      </div>

      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-2">
        <h2 className="text-sm font-bold text-slate-900">AI 위협 분석기</h2>
        <p className="text-xs text-slate-500">
          백엔드 환경변수 <code className="font-mono bg-slate-100 px-1 rounded">GEMINI_API_KEY</code>가
          설정되어 있으면 Gemini 기반 AI 분석이, 없으면 키워드 기반 분석이 자동으로 사용됩니다.
          현재 어떤 방식이 사용됐는지는 각 분석 결과 화면 하단의 "분석 모델" 항목에서 확인할 수 있습니다.
        </p>
      </div>
    </div>
  );
}

export function App() {
  const [activeTab, setActiveTab] = useState('sandbox'); // 'sandbox' | 'transfer-lock' | 'onchain-ledger' | 'settings'
  const [selectedPreset, setSelectedPreset] = useState(ATTACK_PRESETS[0]);
  const [customUrl, setCustomUrl] = useState('');
  const [customText, setCustomText] = useState('');

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [logs, setLogs] = useState([]);
  const [currentAnalysis, setCurrentAnalysis] = useState(null);
  const [analysisTimestamp, setAnalysisTimestamp] = useState(null);
  const [consensusState, setConsensusState] = useState(null);
  const [nodes] = useState(INITIAL_NODES);
  const [threats, setThreats] = useState(localBlockchain.getThreats());

  const [inspectedThreat, setInspectedThreat] = useState(null);
  const [blockedHash, setBlockedHash] = useState(null);
  const [blockHeight, setBlockHeight] = useState(localBlockchain.blockHeight);
  const [isBackendOnline, setIsBackendOnline] = useState(false);

  // --- Mock Bank (demo virtual account) state ---
  const [mockAccount, setMockAccount] = useState(null);
  const [transferAmount, setTransferAmount] = useState(500000);
  const [transferResult, setTransferResult] = useState(null);
  const [isTransferring, setIsTransferring] = useState(false);
  const [isBankBusy, setIsBankBusy] = useState(false);

  // Sync with local blockchain events (used by the on-chain ledger tab)
  useEffect(() => {
    const unsubscribe = localBlockchain.subscribe(({ event, data }) => {
      setThreats(localBlockchain.getThreats());
      setBlockHeight(localBlockchain.blockHeight);
      if (event === 'ThreatEndorsed') {
        setConsensusState((prev) => (prev ? { ...prev, approvalCount: data.approvalCount } : null));
      }
    });
    return () => unsubscribe();
  }, []);

  // Real backend connectivity check
  useEffect(() => {
    let cancelled = false;
    const check = async () => {
      const online = await checkBackendHealth();
      if (!cancelled) setIsBackendOnline(online);
    };
    check();
    const interval = setInterval(check, 10000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  // Load the demo virtual account's real status on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const acc = await fetchMockBankAccount(DEMO_VICTIM_ACCOUNT);
      if (!cancelled && acc) setMockAccount(acc);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // While the demo account is locked, poll so the countdown stays real
  useEffect(() => {
    if (!mockAccount || !mockAccount.locked) return;
    const interval = setInterval(async () => {
      const acc = await fetchMockBankAccount(DEMO_VICTIM_ACCOUNT);
      if (acc) setMockAccount(acc);
    }, 5000);
    return () => clearInterval(interval);
  }, [mockAccount?.locked]);

  const handleSelectPreset = (preset) => {
    setSelectedPreset(preset);
    setCustomUrl('');
    setCustomText('');
    const existing = threats.find((t) => t.url === preset.url && t.isConfirmed);
    setBlockedHash(existing ? existing.apkHash : null);
  };

  const addLog = useCallback((level, message, stage = 'INFO') => {
    const time = new Date().toTimeString().split(' ')[0];
    setLogs((prev) => [...prev, { level, message, stage, timestamp: time }]);
  }, []);

  // Trigger REAL Sandbox Analysis (calls the backend's Playwright-based
  // /api/sandbox/analyze endpoint — no client-side fake simulation).
  const handleTriggerAttack = useCallback(async () => {
    if (isAnalyzing) return;

    const targetUrl = (customUrl || selectedPreset.url || '').trim();
    const targetSms = customText || selectedPreset.smsText || '';

    setIsAnalyzing(true);
    setBlockedHash(null);
    setLogs([]);
    setCurrentAnalysis(null);
    setConsensusState(null);

    if (!targetUrl) {
      addLog('ERROR', '[!] 분석할 URL을 입력해주세요.', 'INPUT_ERROR');
      setIsAnalyzing(false);
      return;
    }

    addLog('INFO', `[*] SafeShield 스미싱/악성코드 실시간 분석 요청 전송: ${targetUrl}`, 'REQUEST');

    try {
      const apiResult = await analyzeUrl(targetUrl, targetSms);
      const analysis = normalizeAnalysis(apiResult);

      if (!analysis.reachable) {
        addLog('ERROR', `[!] 대상에 접속할 수 없습니다: ${analysis.errorDetail || '도메인 접속 불가 / 존재하지 않는 URL'}`, 'SANDBOX');
      } else {
        addLog('SANDBOX', `[+] 실제 페이지 접속 성공 (리다이렉트 ${analysis.redirectChain.length}건)`, 'SANDBOX');
        addLog('ANALYSIS', `[+] 문맥 분석: ${analysis.threatType}`, 'SMS_TRIAGE');

        if (analysis.aiClassifier.used) {
          addLog(
            'ANALYSIS',
            `[🤖] AI 위협 분석: ${analysis.aiClassifier.phishingCategory || ''} · ${analysis.aiClassifier.reasoning}`,
            'AI_CLASSIFIER'
          );
        }

        if (analysis.apkDownloaded && analysis.sha256) {
          addLog('CRYPTO', `[+] 실제 APK 페이로드 다운로드 및 SHA-256 해시 추출 완료: ${analysis.sha256}`, 'APK_INTERCEPT');
        } else {
          addLog('INFO', '[-] 이 페이지에서는 APK 파일이 다운로드되지 않았습니다 (정적 권한 점수 0점).', 'APK_INTERCEPT');
        }

        if (analysis.permissions.length > 0) {
          analysis.permissions.forEach((p) => {
            addLog('WARNING', `    ├── [위험 권한] ${p.permission} -> ${p.name} (${p.danger})`, 'DECOMPILER');
          });
        } else {
          addLog('INFO', '[-] 탐지된 위험 권한 없음.', 'DECOMPILER');
        }
      }

      addLog(
        analysis.riskScore >= 80 ? 'CRITICAL' : analysis.riskScore >= 50 ? 'ALERT' : 'INFO',
        `[결과] AI 위협 점수: ${analysis.riskScore}/100 | 신뢰도: ${analysis.confidenceLevel} | 판정: ${analysis.verdict}`,
        'RISK_EVALUATION'
      );

      if (analysis.locked) {
        if (analysis.justLocked) {
          addLog('BLOCKCHAIN', '[🔒] 이번 탐지로 계좌가 새로 잠금 처리되었습니다 (30분)', 'B2C_ACTION');

          addLog('INFO', '[*] 잠긴 계좌에서 사기범 계좌로 실제 송금 테스트를 시도합니다...', 'B2C_ACTION');
          try {
            const demoTransfer = await attemptMockTransfer(
              DEMO_VICTIM_ACCOUNT,
              DEMO_SCAM_ACCOUNT,
              Number(transferAmount) || 100000
            );
            setTransferResult(demoTransfer);
            if (demoTransfer.account) setMockAccount(demoTransfer.account);
            if (demoTransfer.success) {
              addLog('WARNING', `[!] 예상과 다르게 송금이 완료되었습니다: ${demoTransfer.message}`, 'B2C_ACTION');
            } else {
              addLog('CRITICAL', `[⛔] 송금 시도가 실제로 차단되었습니다: ${demoTransfer.message}`, 'B2C_ACTION');
            }
          } catch (transferErr) {
            addLog('ERROR', `[!] 송금 차단 테스트 요청 실패: ${transferErr.message}`, 'B2C_ACTION');
          }
        } else {
          const remaining = analysis.demoAccount ? analysis.demoAccount.lockRemainingSeconds : null;
          addLog(
            'INFO',
            `[ℹ] 계좌가 이전 탐지로 인해 여전히 잠금 상태입니다 (이번 검사와는 무관${remaining != null ? `, 약 ${remaining}초 남음` : ''})`,
            'B2C_ACTION'
          );
        }
      } else {
        addLog('INFO', '[✓] 스마트 안티 송금 락 미작동 (안전)', 'B2C_ACTION');
      }

      setCurrentAnalysis(analysis);
      setAnalysisTimestamp(new Date().toLocaleString('ko-KR'));
      setBlockedHash(analysis.sha256 && analysis.locked ? analysis.sha256 : null);

      if (analysis.demoAccount) {
        setMockAccount(analysis.demoAccount);
      }
    } catch (err) {
      addLog('ERROR', `[!] 백엔드 연결 실패 또는 분석 오류: ${err.message}`, 'ERROR');
      setCurrentAnalysis(null);
    } finally {
      setIsAnalyzing(false);
    }
  }, [isAnalyzing, customUrl, customText, selectedPreset, addLog, transferAmount]);

  const handleAttemptTransfer = useCallback(async () => {
    setIsTransferring(true);
    setTransferResult(null);
    try {
      const amount = Number(transferAmount);
      const result = await attemptMockTransfer(DEMO_VICTIM_ACCOUNT, DEMO_SCAM_ACCOUNT, amount);
      setTransferResult(result);
      if (result.account) setMockAccount(result.account);
    } catch (err) {
      setTransferResult({ success: false, message: `백엔드 연결 실패: ${err.message}` });
    } finally {
      setIsTransferring(false);
    }
  }, [transferAmount]);

  const handleManualLock = useCallback(async () => {
    setIsBankBusy(true);
    try {
      const acc = await lockMockAccount(DEMO_VICTIM_ACCOUNT, 30, '수동 테스트 잠금 (데모 UI)');
      if (acc) {
        setMockAccount(acc);
        setTransferResult(null);
      }
    } finally {
      setIsBankBusy(false);
    }
  }, []);

  const handleManualUnlock = useCallback(async () => {
    setIsBankBusy(true);
    try {
      const acc = await unlockMockAccount(DEMO_VICTIM_ACCOUNT);
      if (acc) {
        setMockAccount(acc);
        setTransferResult(null);
      }
    } finally {
      setIsBankBusy(false);
    }
  }, []);

  const handleEndorseThreat = (apkHash, nodeAddress) => {
    const updated = localBlockchain.endorseThreat(apkHash, nodeAddress || INITIAL_NODES[1].address);
    setThreats(localBlockchain.getThreats());
    if (updated) setConsensusState(updated);
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex font-sans">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader isBackendOnline={isBackendOnline} />

        <main className="flex-1 overflow-y-auto p-6 space-y-5">
          <div className="flex flex-col gap-1">
            <h1 className="text-xl font-bold text-slate-900">실시간 분석</h1>
            <p className="text-sm text-slate-500">
              의심스러운 문자, 웹 링크를 실제로 접속·분석하여 위험을 탐지합니다.
            </p>
          </div>

          <StepBreadcrumb activeTab={activeTab} setActiveTab={setActiveTab} />

          {activeTab === 'sandbox' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              <section className="lg:col-span-5 xl:col-span-4">
                <ScenarioPanel
                  selectedPreset={selectedPreset}
                  onSelectPreset={handleSelectPreset}
                  customUrl={customUrl}
                  setCustomUrl={setCustomUrl}
                  customText={customText}
                  setCustomText={setCustomText}
                  onTriggerAttack={handleTriggerAttack}
                  isAnalyzing={isAnalyzing}
                />
              </section>
              <section className="lg:col-span-7 xl:col-span-8">
                <AnalysisResultPanel
                  analysis={currentAnalysis}
                  isAnalyzing={isAnalyzing}
                  analysisTimestamp={analysisTimestamp}
                  logs={logs}
                  setActiveTab={setActiveTab}
                />
              </section>
            </div>
          )}

          {activeTab === 'transfer-lock' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              <div className="lg:col-span-8">
                <AntiTransferLockerPage currentAnalysis={currentAnalysis} onNavigateToTab={(tab) => setActiveTab(tab)} />
              </div>
              <div className="lg:col-span-4">
                <MockBankPanel
                  account={mockAccount}
                  transferAmount={transferAmount}
                  setTransferAmount={setTransferAmount}
                  transferResult={transferResult}
                  isTransferring={isTransferring}
                  onAttemptTransfer={handleAttemptTransfer}
                  onManualLock={handleManualLock}
                  onManualUnlock={handleManualUnlock}
                  isBankBusy={isBankBusy}
                />
              </div>
            </div>
          )}

          {activeTab === 'onchain-ledger' && (
            <div className="space-y-4">
              <MultiSigConsensusBar consensusState={consensusState} nodes={nodes} blockHeight={blockHeight} />
              <OnChainDashboard
                threats={threats}
                nodes={nodes}
                onEndorseThreat={handleEndorseThreat}
                onInspectThreat={(threat) => setInspectedThreat(threat)}
              />
            </div>
          )}

          {activeTab === 'settings' && (
            <SettingsPage
              isBackendOnline={isBackendOnline}
              mockAccount={mockAccount}
              onManualLock={handleManualLock}
              onManualUnlock={handleManualUnlock}
              isBankBusy={isBankBusy}
            />
          )}
        </main>

        <footer className="border-t border-slate-200 bg-white py-2 px-6 text-center text-[11px] text-slate-400">
          SafeShield 탈중앙화 사이버 보안 방어 시스템 • Solidity 멀티시그 오라클, Playwright AI 샌드박스 & FastAPI 기반
        </footer>
      </div>

      <ThreatDetailModal threat={inspectedThreat} onClose={() => setInspectedThreat(null)} />
    </div>
  );
}
export default App;
