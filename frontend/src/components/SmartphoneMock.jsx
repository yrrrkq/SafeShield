import React, { useState, useEffect } from 'react';
import { 
  Wifi, 
  Battery, 
  Signal, 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  ExternalLink, 
  MessageSquare, 
  ChevronRight, 
  Send, 
  Clock, 
  Info,
  Smartphone,
  Sparkles,
  Download,
  PowerOff,
  Lock,
  RefreshCw,
  EyeOff,
  Search,
  CheckCircle2
} from 'lucide-react';
import { ATTACK_PRESETS } from '../data/presets';

export function SmartphoneMock({ 
  selectedPreset, 
  onSelectPreset, 
  onTriggerAttack, 
  isAnalyzing, 
  blockedHash,
  customUrl,
  setCustomUrl,
  customText,
  setCustomText,
  safeShieldEnabled = true,
  onToggleSafeShield
}) {
  const [showCustomInput, setShowCustomInput] = useState(false);
  const [unprotectedStage, setUnprotectedStage] = useState('idle'); // idle, downloading, installing, hijacked, blackout
  const isBlocked = Boolean(blockedHash);

  // If safeShield is enabled, reset any unprotected attack stage
  useEffect(() => {
    if (safeShieldEnabled) {
      setUnprotectedStage('idle');
    }
  }, [safeShieldEnabled]);

  const handleLinkClick = (e) => {
    e.preventDefault();
    if (isAnalyzing) return;

    if (!safeShieldEnabled) {
      // Simulate unprotected victim phishing damage sequence ONLY when user explicitly turned OFF protection
      runUnprotectedAttackSequence();
    } else {
      // Run SafeShield AI Sandbox + On-chain consensus (Protected Mode)
      setUnprotectedStage('idle');
      onTriggerAttack();
    }
  };

  const runUnprotectedAttackSequence = () => {
    setUnprotectedStage('downloading');
    setTimeout(() => {
      setUnprotectedStage('installing');
      setTimeout(() => {
        setUnprotectedStage('hijacked');
        setTimeout(() => {
          setUnprotectedStage('blackout');
        }, 2000);
      }, 1600);
    }, 1000);
  };

  const resetPhone = () => {
    setUnprotectedStage('idle');
    if (onToggleSafeShield) {
      onToggleSafeShield(true);
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#0b1120] border border-slate-800/80 rounded-2xl p-4 shadow-2xl relative overflow-hidden">
      
      {/* Panel Header */}
      <div className="flex items-center justify-between pb-2.5 border-b border-slate-800 mb-2.5">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400">
            <Smartphone className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white">1. Smishing Attack Vector</h2>
            <p className="text-[11px] text-slate-400">Victim Smartphone UI Mock</p>
          </div>
        </div>

        {/* Protection Mode Switch */}
        <button
          onClick={() => {
            if (onToggleSafeShield) onToggleSafeShield(!safeShieldEnabled);
          }}
          className={`flex items-center gap-1 text-[11px] font-semibold px-2.5 py-1 rounded-full border transition-all ${
            safeShieldEnabled
              ? "bg-emerald-950/80 border-emerald-500/70 text-emerald-300 glow-emerald"
              : "bg-red-950/80 border-red-500/70 text-red-300 glow-red"
          }`}
          title="Toggle SafeShield Protection"
        >
          {safeShieldEnabled ? (
            <>
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>SafeShield ON</span>
            </>
          ) : (
            <>
              <ShieldAlert className="w-3.5 h-3.5 text-red-400 animate-pulse" />
              <span>보호 OFF (피해 체험)</span>
            </>
          )}
        </button>
      </div>

      {/* Preset Selector Bar */}
      <div className="mb-2.5">
        <div className="flex items-center justify-between mb-1">
          <label className="text-[11px] font-medium text-slate-400 flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-cyan-400" />
            <span>Select Scenario:</span>
          </label>
          <button
            onClick={() => setShowCustomInput(!showCustomInput)}
            className="text-[10px] text-cyan-400 hover:text-cyan-300 underline"
          >
            {showCustomInput ? "Hide Custom" : "Custom SMS"}
          </button>
        </div>

        <div className="grid grid-cols-2 gap-1.5">
          {ATTACK_PRESETS.map((preset) => {
            const isSelected = selectedPreset.id === preset.id;
            return (
              <button
                key={preset.id}
                onClick={() => {
                  onSelectPreset(preset);
                  setShowCustomInput(false);
                  setUnprotectedStage('idle');
                }}
                className={`flex items-center gap-1.5 p-1.5 rounded-lg text-left transition-all border ${
                  isSelected
                    ? "bg-cyan-950/60 border-cyan-500/70 text-cyan-200 glow-cyan"
                    : "bg-slate-900/60 border-slate-800/80 text-slate-300 hover:border-slate-700 hover:bg-slate-800/50"
                }`}
              >
                <span className="text-sm">{preset.icon}</span>
                <div className="truncate">
                  <div className="text-[10px] font-semibold truncate leading-tight">{preset.category}</div>
                  <div className="text-[9px] text-slate-400 truncate">{preset.title.slice(0, 16)}...</div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Custom Input Drawer (Optional) */}
      {showCustomInput && (
        <div className="p-2 mb-2 rounded-lg bg-slate-900 border border-slate-800 text-xs space-y-1.5">
          <div>
            <label className="text-[9px] text-slate-400 block mb-0.5">Custom SMS Text:</label>
            <input
              type="text"
              value={customText}
              onChange={(e) => setCustomText(e.target.value)}
              placeholder="[택배] 배송지 주소 불일치 확인..."
              className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="text-[9px] text-slate-400 block mb-0.5">Malicious URL:</label>
            <input
              type="text"
              value={customUrl}
              onChange={(e) => setCustomUrl(e.target.value)}
              placeholder="http://malicious-site.com/fake.apk"
              className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>
      )}

      {/* Smartphone Device Frame */}
      <div className="flex-1 flex justify-center items-center py-1">
        <div className="w-full max-w-[310px] bg-[#000000] rounded-[36px] border-[5px] border-slate-700 shadow-[0_0_30px_rgba(0,0,0,0.8)] relative flex flex-col overflow-hidden h-[470px]">
          
          {/* Top Notch / Dynamic Island */}
          <div className="w-full pt-2 px-5 flex items-center justify-between text-[10px] font-semibold text-slate-300 z-20">
            <span>12:45</span>
            <div className="w-14 h-3.5 bg-black rounded-full border border-slate-800"></div>
            <div className="flex items-center gap-1 text-slate-300">
              <Signal className="w-3 h-3" />
              <Wifi className="w-3 h-3" />
              <Battery className="w-3.5 h-3.5" />
            </div>
          </div>

          {/* Smartphone Screen Content */}
          <div className="flex-1 bg-gradient-to-b from-[#0f172a] via-[#090e1a] to-[#050811] flex flex-col p-2.5 text-slate-100 relative overflow-hidden">
            
            {/* UNPROTECTED ATTACK STATE (보호 OFF 모드에서만 실행) */}
            {unprotectedStage === 'downloading' && (
              <div className="absolute inset-0 bg-slate-950/95 z-30 flex flex-col items-center justify-center p-4 text-center space-y-3 animate-fadeIn">
                <div className="p-3 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500 animate-bounce">
                  <Download className="w-8 h-8" />
                </div>
                <div className="text-xs font-bold text-white">악성 APK 다운로드 중...</div>
                <div className="w-48 bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div className="bg-blue-500 h-full w-4/5 animate-pulse"></div>
                </div>
                <p className="text-[10px] text-slate-400 font-mono">
                  {selectedPreset.id}_payload.apk (12.4 MB)
                </p>
              </div>
            )}

            {unprotectedStage === 'installing' && (
              <div className="absolute inset-0 bg-slate-950/95 z-30 flex flex-col items-center justify-center p-4 text-center space-y-2.5 animate-fadeIn">
                <div className="p-3 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500 animate-spin">
                  <RefreshCw className="w-7 h-7" />
                </div>
                <div className="text-xs font-bold text-amber-300">악성 스파이웨어 자동 설치 중...</div>
                <div className="p-2 bg-slate-900 border border-red-500/50 rounded-lg text-[10px] text-red-300 text-left w-full space-y-1">
                  <div>🚨 [권한 탈취] 접근성 서비스 강제 활성화</div>
                  <div>🚨 [권한 탈취] SMS 가로채기 & 통화 리디렉션</div>
                  <div>🚨 [권한 탈취] 화면 위 가짜 금융 오버레이 생성</div>
                </div>
              </div>
            )}

            {unprotectedStage === 'hijacked' && (
              <div className="absolute inset-0 bg-red-950/95 z-30 flex flex-col items-center justify-center p-4 text-center space-y-3 animate-pulse">
                <ShieldAlert className="w-10 h-10 text-red-400" />
                <div className="text-sm font-black text-white">스마트폰 원격 제어 탈취됨!</div>
                <p className="text-[10px] text-red-200">
                  사기범이 접근성 권한을 이용해 화면을 조작하고 있습니다.
                </p>
                <div className="text-[10px] font-mono bg-black/60 p-2 rounded text-cyan-300 border border-slate-700">
                  Stealing SMS OTP: [884192]...
                </div>
              </div>
            )}

            {unprotectedStage === 'blackout' && (
              <div className="absolute inset-0 bg-black z-30 flex flex-col items-center justify-center p-4 text-center space-y-3 animate-fadeIn">
                <div className="w-10 h-10 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center text-slate-500">
                  <PowerOff className="w-5 h-5" />
                </div>
                <div className="text-xs font-bold text-slate-300">화면 블랙아웃 (피싱 피해)</div>
                <p className="text-[10px] text-slate-400 leading-tight">
                  피해자가 112에 신고하지 못하도록 사기범이 화면을 끄고 뒤에서 계좌 이체를 진행 중입니다.
                </p>
                <button
                  onClick={resetPhone}
                  className="mt-2 px-3 py-1.5 bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-bold text-xs rounded-xl shadow-lg glow-emerald"
                >
                  🛡️ SafeShield 켜고 복구하기
                </button>
              </div>
            )}

            {/* PROTECTED VIEW (SafeShield ON 모드) */}
            {/* SafeShield Top Status Banner */}
            <div className={`p-2 rounded-xl border mb-2 transition-all duration-300 ${
              isBlocked
                ? "bg-emerald-950/80 border-emerald-500/80 text-emerald-200 glow-emerald"
                : isAnalyzing
                ? "bg-cyan-950/80 border-cyan-500/80 text-cyan-200 glow-cyan"
                : safeShieldEnabled
                ? "bg-emerald-950/50 border-emerald-500/40 text-emerald-300"
                : "bg-red-950/40 border-red-500/30 text-red-300"
            }`}>
              <div className="flex items-center gap-2">
                {isBlocked ? (
                  <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : isAnalyzing ? (
                  <div className="w-3.5 h-3.5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin shrink-0"></div>
                ) : safeShieldEnabled ? (
                  <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <EyeOff className="w-4 h-4 text-red-400 shrink-0" />
                )}
                <div className="leading-tight">
                  <div className="text-[10px] font-bold flex items-center gap-1">
                    {isBlocked
                      ? "🛡️ 악성 앱 설치 차단 완료 (안전)"
                      : isAnalyzing
                      ? "🔍 AI 샌드박스 정밀 검사 중..."
                      : safeShieldEnabled
                      ? "SafeShield 실시간 방어 중"
                      : "⚠️ 보호 기능 해제됨 (피해 체험 가능)"}
                  </div>
                  <div className="text-[9px] opacity-80">
                    {isBlocked
                      ? "온체인 합의로 악성 바이너리가 격리되었습니다."
                      : isAnalyzing
                      ? "가상 브라우저에서 위험도를 분석하고 있습니다."
                      : safeShieldEnabled
                      ? "스미싱 문자 및 링크를 실시간 감시합니다."
                      : "링크 클릭 시 실제 피싱 피해 과정을 체험합니다."}
                  </div>
                </div>
              </div>
            </div>

            {/* Messaging App Header */}
            <div className="flex items-center justify-between pb-1.5 border-b border-slate-800 text-xs text-slate-300 mb-2">
              <div className="flex items-center gap-1.5">
                <div className="w-6 h-6 rounded-full bg-slate-800 flex items-center justify-center font-bold text-xs text-cyan-400">
                  {selectedPreset.icon}
                </div>
                <div>
                  <div className="font-semibold text-white text-[11px]">{selectedPreset.senderNumber}</div>
                  <div className="text-[8px] text-slate-400">Unknown Sender</div>
                </div>
              </div>
              <span className="text-[9px] text-slate-400">{selectedPreset.timestamp}</span>
            </div>

            {/* Inbound SMS Message Feed */}
            <div className="space-y-2 flex-1 overflow-y-auto">
              <div className="flex flex-col items-start max-w-[95%]">
                <div className={`p-2.5 rounded-2xl rounded-tl-sm text-xs transition-all border ${
                  isBlocked
                    ? "bg-slate-900 border-emerald-500/50 text-slate-200"
                    : "bg-slate-900/90 border-slate-700/80 text-slate-200"
                }`}>
                  <p className="leading-relaxed text-[10px] whitespace-pre-wrap">
                    {customText || selectedPreset.smsText}
                  </p>

                  {/* Clickable Phishing Link */}
                  <div className="mt-2 pt-1.5 border-t border-slate-800">
                    <button
                      onClick={handleLinkClick}
                      disabled={isAnalyzing}
                      className={`w-full group text-left p-1.5 rounded-lg border transition-all flex items-center justify-between ${
                        isBlocked
                          ? "bg-emerald-950/70 border-emerald-500 text-emerald-200 cursor-not-allowed"
                          : "bg-blue-950/60 border-blue-500/60 text-blue-300 hover:bg-blue-900/60 hover:border-blue-400"
                      }`}
                    >
                      <div className="truncate pr-1">
                        <span className="text-[8px] block text-slate-400 font-mono">
                          {isBlocked ? "🛡️ BLOCKED MALICIOUS LINK:" : "🔗 TAP LINK TO TEST:"}
                        </span>
                        <span className={`text-[10px] font-mono font-semibold truncate block ${
                          isBlocked ? "text-emerald-300 line-through" : "text-cyan-300"
                        }`}>
                          {customUrl || selectedPreset.url}
                        </span>
                      </div>
                      <ExternalLink className="w-3 h-3 shrink-0 text-cyan-400 group-hover:translate-x-0.5 transition-transform" />
                    </button>
                  </div>
                </div>
                <span className="text-[8px] text-slate-500 mt-1 ml-1 flex items-center gap-1">
                  <Clock className="w-2.5 h-2.5" /> SMS Received
                </span>
              </div>

              {/* LIVE ANALYZING CARD (SafeShield ON) */}
              {isAnalyzing && (
                <div className="p-2.5 bg-cyan-950/80 border border-cyan-500/60 rounded-xl text-[10px] text-cyan-200 animate-pulse space-y-1">
                  <div className="font-bold flex items-center gap-1.5 text-cyan-300">
                    <Search className="w-3.5 h-3.5 animate-spin" />
                    <span>클라우드 샌드박스에서 링크 분석 중...</span>
                  </div>
                  <p className="text-[9px] text-slate-300 leading-tight">
                    내 스마트폰 대신 가상 헤드리스 크롬이 사이트에 방문하여 악성 APK 다운로드를 가로채고 있습니다.
                  </p>
                </div>
              )}

              {/* BLOCKED ALERT CARD (SafeShield ON) */}
              {isBlocked && (
                <div className="p-2.5 bg-emerald-950/90 border border-emerald-500 rounded-xl text-[10px] text-emerald-200 glow-emerald space-y-1 animate-fadeIn">
                  <div className="font-bold flex items-center gap-1.5 text-emerald-300">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>🛡️ 온체인 다중서명으로 차단 성공!</span>
                  </div>
                  <p className="text-[9px] text-slate-200 leading-tight">
                    KISA & AhnLab 공인 노드 합의(2/2) 완료. 악성 바이너리가 스마트폰에 설치되지 않고 원천 격리되었습니다.
                  </p>
                </div>
              )}
            </div>

            {/* Bottom Simulate Trigger Button */}
            <div className="mt-2 pt-1.5 border-t border-slate-800">
              <button
                onClick={safeShieldEnabled ? onTriggerAttack : runUnprotectedAttackSequence}
                disabled={isAnalyzing}
                className={`w-full py-1.5 px-2.5 rounded-xl font-semibold text-[11px] transition-all flex items-center justify-center gap-1.5 shadow-lg ${
                  isAnalyzing
                    ? "bg-slate-800 text-slate-400 cursor-not-allowed"
                    : isBlocked
                    ? "bg-emerald-600 hover:bg-emerald-500 text-white glow-emerald"
                    : safeShieldEnabled
                    ? "bg-gradient-to-r from-cyan-600 via-blue-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white glow-cyan active:scale-95"
                    : "bg-gradient-to-r from-red-600 to-amber-600 hover:from-red-500 hover:to-amber-500 text-white glow-red active:scale-95"
                }`}
              >
                {isAnalyzing ? (
                  <>
                    <div className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    <span>AI 샌드박스 정밀 분석 중...</span>
                  </>
                ) : isBlocked ? (
                  <>
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>다시 테스트하기 (링크 클릭)</span>
                  </>
                ) : safeShieldEnabled ? (
                  <>
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>⚡ SafeShield 실시간 차단 시뮬레이션</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>⚠️ 피싱 피해 체험 (화면 탈취/블랙아웃)</span>
                  </>
                )}
              </button>
            </div>

          </div>

          {/* Home indicator bar */}
          <div className="w-full pb-1 pt-1 bg-black flex justify-center">
            <div className="w-20 h-1 bg-slate-600 rounded-full"></div>
          </div>

        </div>
      </div>

    </div>
  );
}
