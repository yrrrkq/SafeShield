import React from 'react';
import { Radio, CheckCircle2, Shield, Clock, ExternalLink } from 'lucide-react';

export function MultiSigConsensusBar({ consensusState, nodes, blockHeight }) {
  return (
    <div className="p-4 rounded-2xl bg-[#0b1120] border border-slate-800/80 shadow-2xl space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Radio className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <span>Web3 멀티시그 오라클 합의 진행률</span>
              <span className="text-xs font-normal text-slate-400 font-mono">(기준: 4개 노드 중 2개 서명 Quorum)</span>
            </h3>
            <p className="text-[11px] text-slate-400">
              국가 사이버안보 기관 및 보안 백신사가 악성코드 해시를 검증하여 온체인 분산 합의를 수행합니다.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className={`text-xs font-bold px-3 py-1 rounded-full font-mono flex items-center gap-1.5 ${
            consensusState?.isConfirmed
              ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40 glow-emerald'
              : 'bg-amber-950 text-amber-400 border border-amber-500/40'
          }`}>
            {consensusState?.isConfirmed ? (
              <>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>멀티시그 합의 도달 (온체인 악성코드 확정)</span>
              </>
            ) : (
              <>
                <Clock className="w-3.5 h-3.5 animate-spin" />
                <span>서명 수집 중 ({consensusState?.approvalCount || 1}/2)</span>
              </>
            )}
          </span>
        </div>
      </div>

      {/* Nodes Voting Status Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-1">
        {nodes.map((node) => {
          const hasSigned = consensusState?.endorsers?.some(
            e => e.address.toLowerCase() === node.address.toLowerCase()
          ) || (consensusState?.proposer?.toLowerCase() === node.address.toLowerCase());

          return (
            <div
              key={node.id}
              className={`p-3 rounded-xl border transition-all flex flex-col justify-between ${
                hasSigned
                  ? 'bg-emerald-950/40 border-emerald-500/60 text-emerald-200 glow-emerald'
                  : 'bg-slate-900/60 border-slate-800 text-slate-400'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-bold text-white flex items-center gap-1.5">
                  <span>{node.avatar || '🛡️'}</span>
                  <span>{node.shortName || node.name}</span>
                </span>
                <span>
                  {hasSigned ? (
                    <span className="flex items-center gap-1 text-[10px] font-bold text-emerald-400 bg-emerald-950 px-1.5 py-0.5 rounded border border-emerald-500/40">
                      <CheckCircle2 className="w-3 h-3" /> 승인됨
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono text-slate-500">대기 중</span>
                  )}
                </span>
              </div>

              <div className="text-[10px] font-mono text-slate-400 truncate">
                주소: {node.address.slice(0, 10)}...{node.address.slice(-6)}
              </div>

              <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px]">
                <span className="text-slate-500">역할: {node.type}</span>
                <span className={hasSigned ? 'text-emerald-400 font-semibold' : 'text-slate-500'}>
                  {hasSigned ? '블록 포함 완료' : '트랜잭션 대기'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
