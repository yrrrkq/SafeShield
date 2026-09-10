import React, { useEffect, useState } from 'react';
import { ShieldAlert, Radio, Zap, X, CheckCircle, ExternalLink, Cpu } from 'lucide-react';

export function GlobalBroadcastAlert({ broadcastData, onClose }) {
  if (!broadcastData) return null;

  return (
    <div className="fixed top-16 left-1/2 -translate-x-1/2 z-50 w-[94%] max-w-3xl animate-flash-broadcast">
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-red-950/95 via-purple-950/95 to-cyan-950/95 border-2 border-red-500 shadow-[0_0_50px_rgba(255,0,85,0.6)] p-4 text-white backdrop-blur-xl">
        
        {/* Animated Background Laser Glow */}
        <div className="absolute inset-0 bg-gradient-to-r from-red-500/10 via-cyan-500/10 to-transparent animate-pulse pointer-events-none"></div>

        <div className="relative z-10 flex items-start justify-between gap-3">
          
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-xl bg-red-600/30 border border-red-500/60 text-red-400 shrink-0 glow-red">
              <Radio className="w-6 h-6 animate-ping" />
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded bg-red-600 text-white font-black text-[10px] uppercase tracking-wider font-mono">
                  1초 글로벌 온체인 브로드캐스트
                </span>
                <span className="text-xs font-mono text-cyan-300">
                  이벤트: SafeShieldOracle.MalwareConfirmed
                </span>
              </div>

              <h2 className="text-sm sm:text-base font-bold text-white leading-tight">
                🚨 제로데이 악성코드 온체인 확정 & 전 세계 즉각 차단 전파 완료!
              </h2>

              <p className="text-xs text-slate-300">
                위협 분류: <strong className="text-red-300">{broadcastData.threatType}</strong> | 멀티시그 합의 완료 (2/2 노드 서명).
              </p>

              {/* SHA-256 Hash Display */}
              <div className="p-1.5 rounded-lg bg-black/60 border border-slate-700 font-mono text-[11px] text-cyan-300 truncate max-w-xl">
                SHA-256: {broadcastData.apkHash}
              </div>

              {/* Network Broadcast Scope Metrics */}
              <div className="flex flex-wrap items-center gap-3 text-[10px] text-slate-300 pt-1">
                <span className="flex items-center gap-1 text-emerald-400">
                  <CheckCircle className="w-3 h-3" /> 통신사(SKT/KT/LGU+) 및 금융사 SDK에 1.1초 만에 차단 전파
                </span>
                <span className="text-slate-500">|</span>
                <span className="font-mono text-slate-300">
                  트랜잭션: {broadcastData.confirmTxHash?.slice(0, 16) || "0x98f4..."}...
                </span>
                <span className="text-slate-500">|</span>
                <span className="font-mono text-cyan-400">
                  블록 #{broadcastData.blockNumber || 4281941}
                </span>
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>

        </div>

      </div>
    </div>
  );
}
