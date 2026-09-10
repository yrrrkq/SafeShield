import React, { useState } from 'react';
import { X, Copy, Check, Shield, Code, FileText, Database, Radio, CheckCircle } from 'lucide-react';

export function ThreatDetailModal({ threat, onClose }) {
  const [activeTab, setActiveTab] = useState('overview'); // overview, raw, solidity
  const [copied, setCopied] = useState(false);

  if (!threat) return null;

  const copyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(threat, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#0b1120] border border-cyan-500/40 rounded-2xl max-w-2xl w-full p-5 shadow-[0_0_50px_rgba(0,240,255,0.25)] flex flex-col max-h-[85vh] text-slate-200">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">온체인 위협 포렌식 정밀 검사기</h2>
              <p className="text-xs text-slate-400 font-mono">컨트랙트: 0x5FbDB2315678afecb367f032d93F642f64180aa3</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 pt-3 pb-2">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'overview'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/50'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            위협 개요
          </button>
          <button
            onClick={() => setActiveTab('solidity')}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition-all flex items-center gap-1 ${
              activeTab === 'solidity'
                ? 'bg-purple-950 text-purple-300 border border-purple-500/50'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Code className="w-3 h-3" />
            Solidity 호출 트레이스
          </button>
          <button
            onClick={() => setActiveTab('raw')}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition-all flex items-center gap-1 ${
              activeTab === 'raw'
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/50'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <FileText className="w-3 h-3" />
            원장 JSON 원본
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto py-2 space-y-3 pr-1 text-xs">
          {activeTab === 'overview' && (
            <div className="space-y-3">
              {/* Threat Hash */}
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1">APK SHA-256 고유 지문</label>
                <div className="p-2 rounded bg-slate-950 font-mono text-cyan-300 break-all select-all border border-slate-800">
                  {threat.apkHash}
                </div>
              </div>

              {/* Status & Risk */}
              <div className="grid grid-cols-2 gap-2">
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-400 uppercase font-bold block">온체인 상태</span>
                  <span className={`text-sm font-bold mt-1 inline-block ${
                    threat.isConfirmed ? 'text-emerald-400' : 'text-amber-400'
                  }`}>
                    {threat.isConfirmed ? '차단 확정 (CONFIRMED)' : '멀티시그 서명 대기 중'}
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-400 uppercase font-bold block">AI 위험도 점수</span>
                  <span className="text-sm font-bold text-red-400 mt-1 inline-block">
                    {threat.threatScore} / 100 ({threat.threatType})
                  </span>
                </div>
              </div>

              {/* Permissions */}
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1.5">탐지된 Android 위험 권한</label>
                <div className="flex flex-wrap gap-1">
                  {threat.detectedPermissions?.map((perm, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 font-mono text-[10px] text-slate-300">
                      {perm}
                    </span>
                  ))}
                </div>
              </div>

              {/* Signatures */}
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1.5">다중 서명 검증 기관 ({threat.endorsers?.length || 1}개 노드)</label>
                <div className="space-y-1.5">
                  {threat.endorsers?.map((e, idx) => (
                    <div key={idx} className="flex items-center justify-between p-1.5 rounded bg-slate-950 border border-slate-800 text-[11px]">
                      <div className="flex items-center gap-1.5">
                        <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="font-semibold text-white">{e.name}</span>
                      </div>
                      <span className="font-mono text-slate-400 text-[10px]">{e.address}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'solidity' && (
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-purple-300 space-y-2 overflow-x-auto">
              <p className="text-slate-400">// Solidity 스마트 컨트랙트 호출 내역</p>
              <p className="text-cyan-300">
                1. SafeShieldOracle.proposeThreat(<br/>
                &nbsp;&nbsp;bytes32("{threat.apkHash.slice(0, 18)}..."),<br/>
                &nbsp;&nbsp;"{threat.url}",<br/>
                &nbsp;&nbsp;"{threat.threatType}",<br/>
                &nbsp;&nbsp;uint8({threat.threatScore}),<br/>
                &nbsp;&nbsp;[/* 위험 권한 {threat.detectedPermissions?.length || 0}개 */]<br/>
                ); // 발신자: KISA 노드
              </p>
              <p className="text-emerald-300">
                2. SafeShieldOracle.endorseThreat(<br/>
                &nbsp;&nbsp;bytes32("{threat.apkHash.slice(0, 18)}...")<br/>
                ); // 발신자: AhnLab 노드 (2/2 합의 성립)
              </p>
              <p className="text-amber-300">
                3. 발생된 이벤트: MalwareConfirmed(<br/>
                &nbsp;&nbsp;apkHash: {threat.apkHash.slice(0, 18)}...,<br/>
                &nbsp;&nbsp;url: "{threat.url}",<br/>
                &nbsp;&nbsp;confirmedAt: {threat.confirmedAt || Math.floor(Date.now()/1000)}<br/>
                ); // 전 세계 1초 즉각 차단 브로드캐스트
              </p>
            </div>
          )}

          {activeTab === 'raw' && (
            <div className="relative">
              <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-emerald-300 overflow-x-auto max-h-72">
                {JSON.stringify(threat, null, 2)}
              </pre>
              <button
                onClick={copyJson}
                className="absolute top-2 right-2 px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px] flex items-center gap-1 border border-slate-700"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? "복사됨" : "JSON 복사"}</span>
              </button>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="pt-3 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold transition-colors"
          >
            검사기 닫기
          </button>
        </div>

      </div>
    </div>
  );
}
