import React, { useState, useEffect } from 'react';
import { 
  Lock, 
  Unlock, 
  ShieldAlert, 
  ShieldCheck, 
  Clock, 
  AlertTriangle, 
  Building2, 
  Smartphone, 
  CreditCard, 
  CheckCircle2, 
  RefreshCw,
  Zap,
  ArrowRight,
  Eye,
  Key
} from 'lucide-react';

export function AntiTransferLockerPage({ currentAnalysis, onNavigateToTab }) {
  // Transfer lock state
  const isHighThreat = currentAnalysis ? currentAnalysis.riskScore >= 80 : true;
  const [isLocked, setIsLocked] = useState(isHighThreat);
  const [secondsRemaining, setSecondsRemaining] = useState(30 * 60); // 30 minutes countdown
  const [testBankMessage, setTestBankMessage] = useState(null);

  // Sync with current analysis risk score if it changes
  useEffect(() => {
    if (currentAnalysis) {
      setIsLocked(currentAnalysis.riskScore >= 80);
      if (currentAnalysis.riskScore >= 80) {
        setSecondsRemaining(30 * 60);
      }
    }
  }, [currentAnalysis]);

  // Live Countdown timer
  useEffect(() => {
    let timer = null;
    if (isLocked && secondsRemaining > 0) {
      timer = setInterval(() => {
        setSecondsRemaining(prev => Math.max(0, prev - 1));
      }, 1000);
    }
    return () => clearInterval(timer);
  }, [isLocked, secondsRemaining]);

  const formatTime = (secs) => {
    const mins = Math.floor(secs / 60);
    const s = secs % 60;
    return `${mins.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  const handleTestTransferAttempt = (bankName) => {
    if (isLocked) {
      setTestBankMessage({
        type: 'BLOCKED',
        bank: bankName,
        title: `[${bankName}] 이체 실행 차단됨`,
        message: 'SafeShield 금융사기 방어 시스템에 의해 모바일 뱅킹 송금이 30분간 긴급 동결되었습니다. (금융사기 피해 방지)'
      });
    } else {
      setTestBankMessage({
        type: 'ALLOWED',
        bank: bankName,
        title: `[${bankName}] 송금 가능`,
        message: '송금 락이 해제된 상태입니다. 일반적인 이체가 가능합니다.'
      });
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 animate-fadeIn py-2">
      
      {/* Top Header Banner */}
      <div className={`p-6 rounded-2xl border shadow-2xl transition-all ${
        isLocked 
          ? 'bg-gradient-to-r from-red-950/70 via-slate-900/90 to-red-950/50 border-red-500/60 glow-red' 
          : 'bg-gradient-to-r from-emerald-950/70 via-slate-900/90 to-slate-900/60 border-emerald-500/50 glow-emerald'
      }`}>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className={`p-3.5 rounded-2xl border ${
              isLocked 
                ? 'bg-red-500/20 border-red-500/60 text-red-400 animate-pulse' 
                : 'bg-emerald-500/20 border-emerald-500/60 text-emerald-400'
            }`}>
              {isLocked ? <Lock className="w-8 h-8" /> : <Unlock className="w-8 h-8" />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-bold text-white">스마트 안티 송금 일시정지 락커</h2>
                <span className={`px-2.5 py-0.5 text-xs font-bold font-mono rounded-full border ${
                  isLocked 
                    ? 'bg-red-950 text-red-300 border-red-500/60' 
                    : 'bg-emerald-950 text-emerald-300 border-emerald-500/60'
                }`}>
                  {isLocked ? 'ACTIVE LOCK (동결 작동 중)' : 'UNLOCKED (정상)'}
                </span>
              </div>
              <p className="text-sm text-slate-300 mt-1">
                {isLocked
                  ? 'CRITICAL THREAT DETECTED: 고위험 스미싱/도청 악성코드 감지로 모바일 뱅킹 송금이 30분간 긴급 동결되었습니다.'
                  : '현재 등록된 금융 위험이 없거나 동결이 수동 해제되어 일반 송금이 가능합니다.'}
              </p>
            </div>
          </div>

          {/* 30-Minute Live Countdown Gauge */}
          <div className="flex flex-col items-center md:items-end bg-slate-950/90 p-4 rounded-xl border border-slate-800 shrink-0 w-full md:w-auto">
            <span className="text-[11px] text-slate-400 font-medium uppercase tracking-wider flex items-center gap-1.5 mb-1">
              <Clock className="w-3.5 h-3.5 text-red-400" /> 긴급 송금 락 잔여 시간
            </span>
            <div className="text-3xl font-black font-mono tracking-wider text-red-400 glow-red">
              {isLocked ? formatTime(secondsRemaining) : "00:00"}
            </div>
            <div className="w-36 bg-slate-800 h-1.5 rounded-full overflow-hidden mt-2">
              <div 
                className="bg-red-500 h-full transition-all duration-1000"
                style={{ width: `${isLocked ? (secondsRemaining / (30 * 60)) * 100 : 0}%` }}
              ></div>
            </div>
          </div>
        </div>

        {/* Quick Toggle Controls */}
        <div className="mt-5 pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2 text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>금융보안원 및 18개 시중은행 오픈뱅킹 공동 연동 프로토콜</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setIsLocked(true);
                setSecondsRemaining(30 * 60);
              }}
              className="px-3 py-1.5 rounded-lg bg-red-900/60 hover:bg-red-800 border border-red-500/50 text-red-200 font-semibold transition-all"
            >
              🔒 30분 동결 강제 발동 테스트
            </button>
            <button
              onClick={() => setIsLocked(false)}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold transition-all"
            >
              🔓 동결 해제
            </button>
          </div>
        </div>
      </div>

      {/* 3 Core Asset Protection Shields */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* Shield 1: Open Banking Freeze */}
        <div className="p-5 rounded-2xl bg-[#0b1120] border border-slate-800 flex flex-col justify-between space-y-3 shadow-xl">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-400">
              <Building2 className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">오픈뱅킹 전 금융사 출금 동결</h3>
              <p className="text-[11px] text-slate-400">제1금융권 18개사 + 증권사 계좌</p>
            </div>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            악성 앱이 탈취한 공인인증서나 OTP를 통해 타 은행 계좌 잔액을 한 번에 털어가는 오픈뱅킹 자동 이체를 원천 차단합니다.
          </p>
          <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
            <span className="text-slate-400">동결 상태:</span>
            <span className={`font-bold font-mono ${isLocked ? 'text-red-400' : 'text-slate-400'}`}>
              {isLocked ? '🔒 출금 일괄 차단됨' : '정상'}
            </span>
          </div>
        </div>

        {/* Shield 2: Loan & Account Creation Freeze */}
        <div className="p-5 rounded-2xl bg-[#0b1120] border border-slate-800 flex flex-col justify-between space-y-3 shadow-xl">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
              <CreditCard className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">비대면 대출/카드론 즉시 차단</h3>
              <p className="text-[11px] text-slate-400">신분증 도용 2차 금융 대출 방지</p>
            </div>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            스미싱 기기에서 신분증 사본이나 마이데이터를 이용해 비대면 신용대출 또는 마이너스 통장을 무단 개설하는 행위를 차단합니다.
          </p>
          <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
            <span className="text-slate-400">차단 상태:</span>
            <span className={`font-bold font-mono ${isLocked ? 'text-red-400' : 'text-slate-400'}`}>
              {isLocked ? '🔒 대출 심사 즉시 보류' : '정상'}
            </span>
          </div>
        </div>

        {/* Shield 3: Silent SMS & OTP Protection */}
        <div className="p-5 rounded-2xl bg-[#0b1120] border border-slate-800 flex flex-col justify-between space-y-3 shadow-xl">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400">
              <Smartphone className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">SMS 인증번호 무단 탈취 무력화</h3>
              <p className="text-[11px] text-slate-400">2FA OTP 가로채기 차단</p>
            </div>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            <code className="text-amber-300 bg-slate-900 px-1 rounded">READ_SMS</code> 권한을 가진 악성 트로이목마가 은행 인증번호를 가로채더라도 동결 기간 동안 모든 이체 토큰을 무효화합니다.
          </p>
          <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
            <span className="text-slate-400">인증 보안:</span>
            <span className={`font-bold font-mono ${isLocked ? 'text-emerald-400' : 'text-slate-400'}`}>
              {isLocked ? '🛡️ 토큰 무효화 가동 중' : '대기'}
            </span>
          </div>
        </div>

      </div>

      {/* Simulated Banking Apps Transfer Attempt Test Bench */}
      <div className="p-6 rounded-2xl bg-[#0b1120] border border-slate-800 space-y-4 shadow-xl">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Building2 className="w-5 h-5 text-cyan-400" />
            <span>실제 모바일 뱅킹 송금 시도 시뮬레이션</span>
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            아래 주요 은행 앱 버튼을 클릭하여, 송금 락이 걸려 있을 때 금융사 앱에서 어떻게 즉각 차단되는지 가상 테스트할 수 있습니다.
          </p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
          {['국민은행 (KB스타뱅킹)', '신한은행 (SOL뱅크)', '토스 (Toss)', '카카오뱅크'].map((bank) => (
            <button
              key={bank}
              onClick={() => handleTestTransferAttempt(bank)}
              className="p-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/50 text-left transition-all group"
            >
              <div className="text-xs font-bold text-white group-hover:text-cyan-400 transition-colors">
                {bank}
              </div>
              <div className="text-[10px] text-slate-500 mt-1 flex items-center justify-between">
                <span>송금 시도 테스트</span>
                <ArrowRight className="w-3 h-3 text-slate-600 group-hover:text-cyan-400 transition-colors" />
              </div>
            </button>
          ))}
        </div>

        {/* Test Result Alert Modal/Box */}
        {testBankMessage && (
          <div className={`p-4 rounded-xl border animate-fadeIn ${
            testBankMessage.type === 'BLOCKED'
              ? 'bg-red-950/60 border-red-500/80 text-red-200'
              : 'bg-emerald-950/60 border-emerald-500/80 text-emerald-200'
          }`}>
            <div className="flex items-center gap-2 font-bold text-sm">
              {testBankMessage.type === 'BLOCKED' ? (
                <ShieldAlert className="w-4 h-4 text-red-400" />
              ) : (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              )}
              <span>{testBankMessage.title}</span>
            </div>
            <p className="text-xs mt-1 text-slate-300">
              {testBankMessage.message}
            </p>
          </div>
        )}
      </div>

      {/* Linked Malicious Artifact Summary (if analysis exists) */}
      {currentAnalysis && (
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-slate-400">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span>락 트리거 원인 악성코드:</span>
            <span className="font-mono text-cyan-300 font-semibold">{currentAnalysis.sha256?.slice(0, 18)}...</span>
            <span>(위협 점수: <strong className="text-red-400">{currentAnalysis.riskScore}점</strong>)</span>
          </div>
          {onNavigateToTab && (
            <button
              onClick={() => onNavigateToTab('sandbox')}
              className="text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 text-xs"
            >
              <span>1번 샌드박스 정밀 분석 로그 보러가기</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      )}

    </div>
  );
}
