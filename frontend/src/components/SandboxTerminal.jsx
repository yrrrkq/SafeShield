import React, { useRef, useEffect, useState } from 'react';
import { 
  Terminal, 
  Cpu, 
  Copy, 
  Check, 
  Trash2, 
  Maximize2, 
  Play, 
  Pause, 
  ShieldAlert, 
  CheckCircle2, 
  Flame, 
  Key, 
  Lock, 
  Code,
  Globe,
  Radio,
  Database,
  ShieldCheck
} from 'lucide-react';

export function SandboxTerminal({
  logs,
  isAnalyzing,
  currentAnalysis,
  consensusState,
  nodes,
  onClearLogs,
  showConsensus = false,
  onNavigateToTab = null
}) {
  const terminalContainerRef = useRef(null);
  const [copiedHash, setCopiedHash] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && terminalContainerRef.current) {
      terminalContainerRef.current.scrollTop = terminalContainerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const getLogBadgeColor = (level) => {
    switch (level) {
      case 'CRITICAL':
      case 'ALERT':
        return 'text-red-400 bg-red-950/80 border-red-500/50';
      case 'WARNING':
        return 'text-amber-400 bg-amber-950/80 border-amber-500/50';
      case 'SANDBOX':
        return 'text-cyan-400 bg-cyan-950/80 border-cyan-500/50';
      case 'DECOMPILER':
        return 'text-purple-400 bg-purple-950/80 border-purple-500/50';
      case 'CRYPTO':
        return 'text-emerald-400 bg-emerald-950/80 border-emerald-500/50';
      case 'BLOCKCHAIN':
        return 'text-blue-400 bg-blue-950/80 border-blue-500/50';
      default:
        return 'text-slate-400 bg-slate-800 border-slate-700';
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#0b1120] border border-slate-800/80 rounded-2xl p-4 shadow-2xl space-y-3">
      
      {/* Panel Header */}
      <div className="flex items-center justify-between pb-2 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Terminal className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white">2. AI 샌드박스 & 디컴파일러</h2>
            <p className="text-[11px] text-slate-400">헤드리스 크롬 가상 실행 + APK 정적 권한 감사</p>
          </div>
        </div>

        {/* Terminal Controls */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`p-1.5 rounded-md border text-xs transition-colors ${
              autoScroll
                ? "bg-cyan-950/60 border-cyan-500/50 text-cyan-300"
                : "bg-slate-800 border-slate-700 text-slate-400"
            }`}
            title={autoScroll ? "자동 스크롤 일시정지" : "자동 스크롤 켜기"}
          >
            {autoScroll ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          </button>
          
          <button
            onClick={onClearLogs}
            className="p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-400 hover:text-white transition-colors"
            title="터미널 로그 지우기"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Real-Time Cyber Terminal Output */}
      <div 
        ref={terminalContainerRef}
        className="h-[230px] bg-[#050811] rounded-xl border border-slate-800/90 p-3 font-mono text-xs overflow-y-auto terminal-scroll relative shadow-inner"
      >
        
        {/* Terminal Top Scanline / Status Bar */}
        <div className="flex items-center justify-between text-[10px] text-slate-500 pb-2 mb-2 border-b border-slate-900 sticky top-0 bg-[#050811]/95 backdrop-blur z-10">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            <span>샌드박스 PID: 88412 [Playwright 격리 브라우저]</span>
          </div>
          <span>메모리: 142MB | CPU: 12.4%</span>
        </div>

        {logs.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 text-xs py-8 space-y-2 text-center">
            <Cpu className="w-8 h-8 text-slate-600 animate-pulse" />
            <p>대기 중. 좌측 스마트폰에서 스미싱 링크를 클릭하면 샌드박스 정밀 분석이 시작됩니다.</p>
          </div>
        ) : (
          <div className="space-y-1.5">
            {logs.map((log, index) => (
              <div key={index} className="flex items-start gap-2 leading-relaxed animate-fadeIn">
                <span className="text-slate-600 select-none text-[10px] pt-0.5">{log.timestamp || "00:00:00"}</span>
                <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold border shrink-0 ${getLogBadgeColor(log.level)}`}>
                  {log.level}
                </span>
                <span className={`text-[11px] ${
                  log.level === 'CRITICAL' || log.level === 'ALERT'
                    ? 'text-red-300 font-semibold'
                    : log.level === 'DECOMPILER'
                    ? 'text-purple-300'
                    : log.level === 'CRYPTO'
                    ? 'text-emerald-300 font-medium'
                    : log.level === 'BLOCKCHAIN'
                    ? 'text-blue-300 font-semibold'
                    : 'text-slate-300'
                }`}>
                  {log.message}
                </span>
              </div>
            ))}
            {isAnalyzing && (
              <div className="flex items-center gap-2 text-cyan-400 text-xs pt-1 animate-pulse">
                <span className="w-1.5 h-3 bg-cyan-400 inline-block animate-pulse"></span>
                <span>AI 바이너리 정적/동적 디컴파일 분석 실행 중...</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Analysis Metrics & Decompiled Artifacts */}
      {currentAnalysis ? (
        <div className="space-y-2.5">
          {/* APK Fingerprint & Threat Score Row */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
            
            {/* Risk Score Gauge */}
            <div className="p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
              <span className="text-[10px] text-slate-400 font-medium uppercase tracking-wider">AI 위험도 점수</span>
              <div className="flex items-baseline gap-1.5 my-1">
                <span className={`text-2xl font-bold font-mono ${
                  currentAnalysis.riskScore >= 80 ? 'text-red-400 glow-red' : 'text-amber-400'
                }`}>
                  {currentAnalysis.riskScore}
                </span>
                <span className="text-xs text-slate-500 font-mono">/ 100</span>
                <span className="ml-auto px-2 py-0.5 text-[10px] font-bold rounded-full bg-red-950 text-red-300 border border-red-500/40">
                  {currentAnalysis.riskScore >= 80 ? "치명적 위협" : "의심"}
                </span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div 
                  className="bg-gradient-to-r from-amber-500 to-red-500 h-full transition-all duration-500"
                  style={{ width: `${currentAnalysis.riskScore}%` }}
                ></div>
              </div>
            </div>

            {/* SHA-256 Fingerprint Card */}
            <div className="md:col-span-2 p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-slate-400 font-medium uppercase tracking-wider flex items-center gap-1">
                  <Key className="w-3 h-3 text-cyan-400" /> 추출된 APK 고유 SHA-256 해시 지문
                </span>
                <button
                  onClick={() => copyToClipboard(currentAnalysis.sha256)}
                  className="flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedHash ? "복사완료!" : "복사"}</span>
                </button>
              </div>
              
              <div className="p-1.5 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-cyan-300 truncate my-1">
                {currentAnalysis.sha256}
              </div>

              <div className="flex items-center justify-between text-[10px] text-slate-400">
                <span>패키지: <strong className="text-slate-300 font-mono">{currentAnalysis.packageName}</strong></span>
                <span>분류: <strong className="text-red-400">{currentAnalysis.threatType}</strong></span>
              </div>
            </div>

          </div>

          {/* Dangerous Android Permissions Card */}
          <div className="p-2.5 rounded-xl bg-slate-900/90 border border-slate-800">
            <span className="text-[10px] text-slate-400 font-medium uppercase tracking-wider block mb-1.5 flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-red-400" />
              탐지된 Android 위험 권한 ({currentAnalysis.permissions?.length || 0}개)
            </span>
            <div className="flex flex-wrap gap-1.5">
              {currentAnalysis.permissions?.map((p, i) => (
                <div 
                  key={i}
                  title={p.description || p.permission}
                  className={`px-2 py-1 rounded-lg text-[10px] font-mono flex items-center gap-1 border ${
                    p.danger === 'CRITICAL'
                      ? 'bg-red-950/80 border-red-500/60 text-red-200'
                      : p.danger === 'HIGH'
                      ? 'bg-amber-950/80 border-amber-500/60 text-amber-200'
                      : 'bg-slate-800 border-slate-700 text-slate-300'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
                  <span className="font-semibold">{p.name || p.permission.split('.').pop()}</span>
                </div>
              ))}
            </div>
          </div>

          {/* B2C Consumer Protection Features: Anti-Transfer Lock & Insurance PoP */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {/* Anti-Transfer Lock Card */}
            <div className={`p-2.5 rounded-xl border flex flex-col justify-between ${
              currentAnalysis.riskScore >= 80
                ? 'bg-red-950/40 border-red-500/50 glow-red'
                : 'bg-slate-900/90 border-slate-800'
            }`}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] text-slate-300 font-bold uppercase tracking-wider flex items-center gap-1">
                  <Lock className={`w-3.5 h-3.5 ${currentAnalysis.riskScore >= 80 ? 'text-red-400' : 'text-slate-400'}`} />
                  스마트 안티 송금 락
                </span>
                <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded font-mono ${
                  currentAnalysis.riskScore >= 80
                    ? 'bg-red-900/80 text-red-200 border border-red-500/60'
                    : 'bg-slate-800 text-slate-400'
                }`}>
                  {currentAnalysis.riskScore >= 80 ? '30분 긴급 동결' : '이체 정상'}
                </span>
              </div>
              <p className="text-[10px] text-slate-300 leading-tight">
                {currentAnalysis.riskScore >= 80
                  ? '⚠️ 고위험 악성코드 감지: 모바일 뱅킹 및 오픈뱅킹 이체가 30분간 자동 차단되었습니다.'
                  : '위협 점수가 안전 기준 내에 있어 금융 이체가 허용됩니다.'}
              </p>
            </div>

            {/* Proof-of-Protection Insurance Card */}
            <div className="p-2.5 rounded-xl bg-slate-900/90 border border-emerald-500/40 glow-emerald flex flex-col justify-between">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] text-slate-300 font-bold uppercase tracking-wider flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  Web3 소액 보험 (PoP)
                </span>
                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded font-mono bg-emerald-950 text-emerald-300 border border-emerald-500/50">
                  {currentAnalysis.riskScore >= 80 ? 'VERIFIED (보장 활성)' : 'STANDBY'}
                </span>
              </div>
              <div className="flex items-center justify-between text-[10px]">
                <span className="text-slate-400">최대 보장 한도:</span>
                <span className="font-bold text-emerald-400 font-mono">3,000,000 KRW</span>
              </div>
              <p className="text-[9px] text-slate-400 mt-0.5">
                피해 발생 시 오라클 스마트 계약을 통해 1.2초 내 즉시 자동 보상됩니다.
              </p>
            </div>
          </div>

          {/* If showConsensus prop is true, show consensus gauge */}
          {showConsensus && (
            <div className="p-2.5 rounded-xl bg-slate-900/90 border border-cyan-900/40 glow-cyan">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] text-slate-300 font-medium uppercase tracking-wider flex items-center gap-1.5">
                  <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                  Web3 멀티시그 오라클 합의 진행률 (기준: 4개 노드 중 2개 서명)
                </span>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full font-mono ${
                  consensusState?.isConfirmed
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40 glow-emerald'
                    : 'bg-amber-950 text-amber-400 border border-amber-500/40'
                }`}>
                  {consensusState?.isConfirmed ? '✅ 멀티시그 합의 도달 (온체인 확정)' : `⏳ 서명 진행 중 (${consensusState?.approvalCount || 1}/2)`}
                </span>
              </div>

              {/* Nodes Voting Status Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
                {nodes.map((node) => {
                  const hasSigned = consensusState?.endorsers?.some(
                    e => e.address.toLowerCase() === node.address.toLowerCase()
                  ) || (consensusState?.proposer?.toLowerCase() === node.address.toLowerCase());

                  return (
                    <div
                      key={node.id}
                      className={`p-1.5 rounded-lg border text-xs flex flex-col justify-between transition-all ${
                        hasSigned
                          ? 'bg-emerald-950/50 border-emerald-500/60 text-emerald-200 glow-emerald'
                          : 'bg-slate-950 border-slate-800 text-slate-500'
                      }`}
                    >
                      <div className="flex items-center justify-between text-[10px]">
                        <span className="font-semibold truncate">{node.shortName || node.name}</span>
                        <span>{hasSigned ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : '⏳'}</span>
                      </div>
                      <div className="text-[9px] font-mono mt-1 truncate opacity-70">
                        {hasSigned ? '서명 완료 (검증됨)' : '서명 대기 중...'}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Quick link buttons to dedicated pages */}
          {onNavigateToTab && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
              <button
                onClick={() => onNavigateToTab('transfer-lock')}
                className="py-2 px-2.5 rounded-xl bg-red-950/40 hover:bg-red-900/40 border border-red-500/30 text-red-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all group"
              >
                <Lock className="w-3.5 h-3.5 text-red-400" />
                <span>2. 송금 락커 확인</span>
                <span className="group-hover:translate-x-0.5 transition-transform text-red-400">→</span>
              </button>

              <button
                onClick={() => onNavigateToTab('insurance-claim')}
                className="py-2 px-2.5 rounded-xl bg-emerald-950/40 hover:bg-emerald-900/40 border border-emerald-500/30 text-emerald-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all group"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>3. 스마트 보험 청구</span>
                <span className="group-hover:translate-x-0.5 transition-transform text-emerald-400">→</span>
              </button>

              <button
                onClick={() => onNavigateToTab('onchain-ledger')}
                className="py-2 px-2.5 rounded-xl bg-blue-950/40 hover:bg-blue-900/40 border border-blue-500/30 text-blue-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all group"
              >
                <Database className="w-3.5 h-3.5 text-blue-400" />
                <span>4. Web3 온체인 원장</span>
                <span className="group-hover:translate-x-0.5 transition-transform text-blue-400">→</span>
              </button>
            </div>
          )}

        </div>
      ) : (
        <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800/80 text-center text-slate-500 text-xs">
          <Globe className="w-6 h-6 mx-auto mb-1.5 text-slate-600" />
          스미싱 링크를 클릭하면 실시간 권한 분석 및 온체인 다중 서명이 시작됩니다.
        </div>
      )}

    </div>
  );
}
