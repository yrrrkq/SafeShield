import React, { useState } from 'react';
import { 
  Database, 
  ShieldCheck, 
  Clock, 
  Key, 
  ExternalLink, 
  CheckCircle, 
  AlertCircle, 
  Radio, 
  PenTool, 
  Search,
  Filter,
  Eye,
  Layers,
  ArrowUpRight
} from 'lucide-react';

export function OnChainDashboard({
  threats,
  nodes,
  onEndorseThreat,
  onInspectThreat
}) {
  const [filter, setFilter] = useState('all'); // all, confirmed, pending
  const [searchQuery, setSearchQuery] = useState('');

  const filteredThreats = threats.filter(threat => {
    if (filter === 'confirmed' && !threat.isConfirmed) return false;
    if (filter === 'pending' && (threat.isConfirmed || threat.isRevoked)) return false;
    
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        threat.apkHash.toLowerCase().includes(q) ||
        threat.threatType.toLowerCase().includes(q) ||
        threat.url.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="flex flex-col h-full bg-[#0b1120] border border-slate-800/80 rounded-2xl p-4 shadow-2xl space-y-3">
      
      {/* Panel Header */}
      <div className="flex items-center justify-between pb-2 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Database className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white">3. Web3 온체인 위협 인텔리전스 원장</h2>
            <p className="text-[11px] text-slate-400">스마트 컨트랙트 실시간 원장 & 오라클 다중 서명</p>
          </div>
        </div>

        {/* Status Indicator */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-[11px] font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
          <span className="text-slate-300">실시간 동기화 중</span>
        </div>
      </div>

      {/* Filter Tabs & Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
          <button
            onClick={() => setFilter('all')}
            className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all ${
              filter === 'all'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/50'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            전체 ({threats.length})
          </button>
          <button
            onClick={() => setFilter('confirmed')}
            className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all flex items-center gap-1 ${
              filter === 'confirmed'
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/50'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <ShieldCheck className="w-3 h-3 text-emerald-400" />
            차단 확정 ({threats.filter(t => t.isConfirmed).length})
          </button>
          <button
            onClick={() => setFilter('pending')}
            className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all flex items-center gap-1 ${
              filter === 'pending'
                ? 'bg-amber-950 text-amber-300 border border-amber-500/50'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Clock className="w-3 h-3 text-amber-400" />
            합의 진행 중 ({threats.filter(t => !t.isConfirmed && !t.isRevoked).length})
          </button>
        </div>

        {/* Search */}
        <div className="relative flex-1 min-w-[150px]">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="SHA-256 해시 / 위협 검색..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-2 py-1 text-slate-300 text-xs focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
      </div>

      {/* Threats On-Chain Feed */}
      <div className="flex-1 overflow-y-auto space-y-2.5 pr-1 max-h-[560px]">
        {filteredThreats.length === 0 ? (
          <div className="h-48 flex flex-col items-center justify-center text-slate-500 text-xs border border-dashed border-slate-800 rounded-xl p-4">
            <Layers className="w-6 h-6 mb-2 text-slate-600" />
            <p>해당 필터에 등록된 온체인 위협 기록이 없습니다.</p>
          </div>
        ) : (
          filteredThreats.map((threat) => {
            const isConfirmed = threat.isConfirmed;
            const approvalCount = threat.approvalCount || 1;
            const requiredSigs = 2;

            return (
              <div
                key={threat.apkHash}
                className={`p-3 rounded-xl border transition-all duration-300 relative overflow-hidden ${
                  isConfirmed
                    ? 'bg-slate-900/90 border-emerald-500/40 glow-emerald'
                    : 'bg-slate-900/70 border-amber-500/40 glow-amber'
                }`}
              >
                {/* Top Row: Threat Type & Status Badge */}
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                      온체인 위협 레코드
                    </span>
                    <h3 className="text-xs font-bold text-white leading-snug">
                      {threat.threatType}
                    </h3>
                  </div>

                  {/* Status Badge */}
                  {isConfirmed ? (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-950/90 text-emerald-300 border border-emerald-500/60 flex items-center gap-1 shrink-0">
                      <ShieldCheck className="w-3 h-3 text-emerald-400" />
                      차단 확정 및 전파 완료 (온체인)
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-950/90 text-amber-300 border border-amber-500/60 flex items-center gap-1 shrink-0 animate-pulse">
                      <Clock className="w-3 h-3 text-amber-400" />
                      멀티시그 서명 진행 중 ({approvalCount}/{requiredSigs})
                    </span>
                  )}
                </div>

                {/* SHA-256 Hash Display */}
                <div className="p-1.5 rounded bg-slate-950 border border-slate-800/80 font-mono text-[11px] text-cyan-300 truncate my-1.5 flex items-center justify-between">
                  <span className="truncate">{threat.apkHash}</span>
                  <span className="text-[9px] text-slate-500 ml-1 shrink-0">SHA-256</span>
                </div>

                {/* Target URL */}
                <div className="text-[11px] text-slate-400 truncate mb-2">
                  <span className="text-slate-500">피싱 URL:</span> <span className="text-slate-300 font-mono">{threat.url}</span>
                </div>

                {/* Multi-Sig Signatures Breakdown */}
                <div className="p-2 rounded-lg bg-slate-950/70 border border-slate-800/80 text-[10px] mb-2">
                  <div className="flex items-center justify-between text-slate-400 mb-1">
                    <span>공인 노드 서명 현황 ({threat.endorsers?.length || 1}/4개 노드):</span>
                    <span className="font-mono text-cyan-400">블록 #{threat.blockNumber || 4281940}</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {threat.endorsers?.map((endorser, idx) => (
                      <span
                        key={idx}
                        className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300 font-medium flex items-center gap-1"
                      >
                        <CheckCircle className="w-2.5 h-2.5 text-emerald-400" />
                        {endorser.name?.split(' ')[0] || "공인 노드"}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Card Actions Footer */}
                <div className="flex items-center justify-between pt-1 border-t border-slate-800/80 text-xs">
                  <button
                    onClick={() => onInspectThreat(threat)}
                    className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 transition-colors"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    <span>스마트 컨트랙트 호출 상세 검사</span>
                  </button>

                  {/* If Pending -> Show Interactive Oracle Sign button */}
                  {!isConfirmed && (
                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => onEndorseThreat(threat.apkHash, nodes[1]?.address)}
                        className="px-2.5 py-1 rounded-md bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-[10px] flex items-center gap-1 shadow-md transition-all active:scale-95"
                      >
                        <PenTool className="w-3 h-3" />
                        <span>안랩 노드로 서명하기 (합의)</span>
                      </button>
                    </div>
                  )}
                </div>

              </div>
            );
          })
        )}
      </div>

    </div>
  );
}
