import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, Cpu, Radio, ExternalLink, RefreshCw, Zap, Smartphone, Database, Lock } from 'lucide-react';

export function Navbar({ activeTab = 'sandbox', setActiveTab, blockHeight, totalBlocked, isConnected, onResetDemo, onQuickAttack }) {
  return (
    <header className="border-b border-slate-800 bg-[#0a0f1d]/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-[1780px] mx-auto px-4 sm:px-6 py-2.5 flex flex-wrap items-center justify-between gap-3">
        
        {/* Brand & Title */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500/20 via-blue-500/20 to-emerald-500/20 border border-cyan-500/50 flex items-center justify-center glow-cyan">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <span className="absolute -top-1 -right-1 w-3 h-3 bg-emerald-500 rounded-full border-2 border-[#0a0f1d] animate-pulse"></span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-lg text-white tracking-wide flex items-center gap-1.5">
                Safe<span className="text-cyan-400">Shield</span>
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-semibold bg-cyan-950/80 text-cyan-400 border border-cyan-500/40 rounded-full font-mono uppercase tracking-wider">
                EVM 위협 오라클 MVP
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              AI 샌드박스 & Web3 온체인 멀티시그 합의 기반 실시간 스미싱/보이스피싱 방어 시스템
            </p>
          </div>
        </div>

        {/* 4 Dedicated Page Switcher Tabs */}
        <div className="flex items-center p-1 bg-slate-950/90 rounded-xl border border-slate-800 shadow-inner">
          <button
            onClick={() => setActiveTab && setActiveTab('sandbox')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'sandbox'
                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/25'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            }`}
          >
            <Smartphone className="w-3.5 h-3.5" />
            <span>1. 스미싱/악성코드 실시간 분석</span>
          </button>

          <button
            onClick={() => setActiveTab && setActiveTab('transfer-lock')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'transfer-lock'
                ? 'bg-red-500 text-white shadow-md shadow-red-500/25'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>2. 송금 일시정지 락커</span>
          </button>

          <button
            onClick={() => setActiveTab && setActiveTab('insurance-claim')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'insurance-claim'
                ? 'bg-emerald-500 text-slate-950 shadow-md shadow-emerald-500/25'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>3. 스마트 보험 청구</span>
          </button>

          <button
            onClick={() => setActiveTab && setActiveTab('onchain-ledger')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'onchain-ledger'
                ? 'bg-blue-500 text-white shadow-md shadow-blue-500/25'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            <span>4. Web3 멀티시그 원장</span>
          </button>
        </div>

        {/* Network & Node Status Badges */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Network Pill */}
          <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs font-mono">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
              <span className="text-slate-300 font-medium">SafeShield L2 서브넷</span>
            </div>
            <span className="text-slate-600">|</span>
            <span className="text-cyan-400">블록 #{blockHeight || 4281940}</span>
          </div>

          {/* Oracles Online */}
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span className="text-slate-400">공인 노드:</span>
            <span className="font-semibold text-emerald-400">4개 정상 가동 (2/4 멀티시그 합의)</span>
          </div>

          {/* Confirmed Threats Counter */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-950/40 border border-red-900/50 text-xs glow-red">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span className="text-slate-300">차단 완료:</span>
            <span className="font-bold font-mono text-emerald-400">{totalBlocked}건 제로데이</span>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={onQuickAttack}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gradient-to-r from-red-600 to-amber-600 hover:from-red-500 hover:to-amber-500 text-white text-xs font-medium rounded-lg shadow-lg transition-all active:scale-95"
            >
              <Zap className="w-3.5 h-3.5 fill-white" />
              <span>공격 시뮬레이션</span>
            </button>

            <button
              onClick={onResetDemo}
              title="데모 초기화"
              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg transition-all"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

      </div>
    </header>
  );
}
