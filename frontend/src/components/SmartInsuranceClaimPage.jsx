import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Zap, 
  CheckCircle2, 
  FileText, 
  Building2, 
  ExternalLink, 
  Clock, 
  DollarSign, 
  Lock, 
  Sparkles,
  ArrowRight,
  Radio,
  Check
} from 'lucide-react';

export function SmartInsuranceClaimPage({ onNavigateToTab }) {
  const [victimId, setVictimId] = useState("victim_citizen_01");
  const [incidentType, setIncidentType] = useState("SMISHING_APK_INTERCEPT");
  const [claiming, setClaiming] = useState(false);
  const [claimResult, setClaimResult] = useState(null);
  const [copiedTx, setCopiedTx] = useState(false);

  const handleClaim = async () => {
    setClaiming(true);
    setClaimResult(null);
    try {
      const res = await fetch("http://localhost:8000/api/insurance/claim-demo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ victim_id: victimId, incident_type: incidentType })
      });
      if (res.ok) {
        const data = await res.json();
        setClaimResult(data);
      } else {
        // Fallback simulation
        setClaimResult({
          status: "SUCCESS",
          oracle_verification: "POLICE_DATA_MATCHED",
          payout_amount: "3,000,000 KRW",
          tx_hash: "0xabc1234567890def1234567890def1234567890def1234567890def123456789",
          message: "Parametric Insurance Payout Approved & Sent in 1.2s"
        });
      }
    } catch (err) {
      setClaimResult({
        status: "SUCCESS",
        oracle_verification: "POLICE_DATA_MATCHED",
        payout_amount: "3,000,000 KRW",
        tx_hash: "0xabc1234567890def1234567890def1234567890def1234567890def123456789",
        message: "Parametric Insurance Payout Approved & Sent in 1.2s"
      });
    } finally {
      setClaiming(false);
    }
  };

  const copyTx = (hash) => {
    navigator.clipboard.writeText(hash);
    setCopiedTx(true);
    setTimeout(() => setCopiedTx(false), 2000);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 animate-fadeIn py-2">
      
      {/* Top Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-emerald-950/60 via-slate-900/90 to-teal-950/60 border border-emerald-500/50 shadow-2xl glow-emerald">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="p-3.5 rounded-2xl bg-emerald-500/20 border border-emerald-500/60 text-emerald-400">
              <ShieldCheck className="w-8 h-8" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-bold text-white">Web3 파라메트릭 소액 보험 스마트 청구 센터</h2>
                <span className="px-2.5 py-0.5 text-xs font-bold font-mono rounded-full bg-emerald-950 text-emerald-300 border border-emerald-500/50">
                  PoP (안전 보호 증명) 연동
                </span>
              </div>
              <p className="text-sm text-slate-300 mt-1">
                복잡한 서류 심사 없이, 스마트 컨트랙트 오라클이 경찰청 사건 데이터를 대조하여 1.2초 만에 즉시 보상금을 자동 지급합니다.
              </p>
            </div>
          </div>

          <div className="flex flex-col items-center md:items-end bg-slate-950/90 p-4 rounded-xl border border-slate-800 shrink-0 w-full md:w-auto">
            <span className="text-[11px] text-slate-400 font-medium uppercase tracking-wider mb-1">
              최대 보장 한도
            </span>
            <div className="text-2xl font-black font-mono tracking-wider text-emerald-400 glow-emerald">
              3,000,000 KRW
            </div>
            <span className="text-[10px] text-emerald-300/80 font-mono mt-1">
              평균 지급 소요 시간: 1.2초
            </span>
          </div>
        </div>
      </div>

      {/* 2-Column Grid: Insurance Policy Certificate + Interactive Claim Simulator */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        
        {/* Left Column: Policy Certificate & Oracle Information (col-span-5) */}
        <div className="lg:col-span-5 space-y-4">
          
          {/* Policy Card */}
          <div className="p-5 rounded-2xl bg-[#0b1120] border border-slate-800 shadow-xl space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <span className="text-xs font-bold text-white flex items-center gap-1.5">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span>디지털 보험증권 (Smart Policy)</span>
              </span>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-500/40">
                #SF-2026-KR8829
              </span>
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">피보험자 ID:</span>
                <span className="text-white font-mono font-semibold">{victimId}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">보험 계약 방식:</span>
                <span className="text-cyan-300 font-medium">파라메트릭 스마트 컨트랙트</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">사용자 자부담금:</span>
                <span className="text-emerald-400 font-bold font-mono">0 KRW (SafeShield 기본 보장)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">Proof-of-Protection:</span>
                <span className="text-emerald-400 font-bold font-mono flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> VERIFIED (유효)
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">지급 합의 방식:</span>
                <span className="text-purple-300 font-mono">경찰청 오라클 노드 자동 서명</span>
              </div>
            </div>
          </div>

          {/* Traditional vs Parametric Comparison Card */}
          <div className="p-5 rounded-2xl bg-[#0b1120] border border-slate-800 shadow-xl space-y-3">
            <h4 className="text-xs font-bold text-white flex items-center gap-1.5">
              <Sparkles className="w-4 h-4 text-amber-400" />
              <span>기존 보험 vs SafeShield 파라메트릭 보상</span>
            </h4>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 text-slate-400 space-y-1">
                <div className="text-[11px] font-bold text-slate-400">기존 금융 손해보험</div>
                <div className="text-[10px] text-slate-500">• 서류 제출: 6종 이상</div>
                <div className="text-[10px] text-slate-500">• 심사 기간: 2주 ~ 4주</div>
                <div className="text-[10px] text-slate-500">• 인적 심사로 지연</div>
              </div>
              <div className="p-2.5 rounded-xl bg-emerald-950/40 border border-emerald-500/40 text-emerald-200 space-y-1 glow-emerald">
                <div className="text-[11px] font-bold text-emerald-400">SafeShield 스마트 청구</div>
                <div className="text-[10px] text-emerald-300">• 서류 필요 없음 (Zero)</div>
                <div className="text-[10px] text-emerald-300">• 심사 시간: <strong>1.2초</strong></div>
                <div className="text-[10px] text-emerald-300">• 오라클 기반 자동 지급</div>
              </div>
            </div>
          </div>

        </div>

        {/* Right Column: Interactive Claim Simulation Form & Live Receipt (col-span-7) */}
        <div className="lg:col-span-7 space-y-4">
          
          {/* Claim Action Box */}
          <div className="p-6 rounded-2xl bg-[#0b1120] border border-slate-800 shadow-xl space-y-4">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Zap className="w-5 h-5 text-emerald-400" />
                <span>원클릭 스마트 보험금 청구 시뮬레이션</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                피해 사건 유형을 선택한 후 청구 버튼을 누르면, 백엔드 스마트 컨트랙트 오라클이 실시간 호출되어 보상금을 즉시 승인합니다.
              </p>
            </div>

            {/* Form Fields */}
            <div className="space-y-3 pt-1">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">피해자 식별자 (Citizen ID)</label>
                <input
                  type="text"
                  value={victimId}
                  onChange={(e) => setVictimId(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">피해 사건 유형</label>
                <select
                  value={incidentType}
                  onChange={(e) => setIncidentType(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="SMISHING_APK_INTERCEPT">스미싱 APK 설치로 인한 무단 금융 송금 피해 (Trojan.Banker)</option>
                  <option value="VOICE_PHISHING_POLICE_SPOOF">가짜 공공기관/검경 사칭 피싱 전화 가로채기 (Trojan.Spy.CallHijack)</option>
                  <option value="CJ_PARCEL_SMS_FRAUD">택배 배송 보류 사칭 결제 도용 피해 (Trojan.Dropper)</option>
                </select>
              </div>
            </div>

            {/* Claim Submit Button */}
            <button
              onClick={handleClaim}
              disabled={claiming}
              className="w-full py-3.5 px-4 rounded-xl bg-gradient-to-r from-emerald-600 via-teal-600 to-emerald-500 hover:from-emerald-500 hover:to-teal-400 text-white text-sm font-bold shadow-xl shadow-emerald-950/60 flex items-center justify-center gap-2 transition-all active:scale-98 disabled:opacity-50"
            >
              {claiming ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  <span>경찰청 오라클 데이터 대조 및 스마트 계약 송금 실행 중...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 fill-white" />
                  <span>1.2초 즉시 파라메트릭 보험금 지급 청구 실행</span>
                </>
              )}
            </button>
          </div>

          {/* Live Payout Transaction Receipt */}
          {claimResult && (
            <div className="p-5 rounded-2xl bg-slate-950 border border-emerald-500/70 shadow-2xl space-y-3 animate-fadeIn glow-emerald">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5" />
                  <span>스마트 컨트랙트 보상금 지급 영수증</span>
                </span>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-500/50">
                  {claimResult.status}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                  <span className="text-slate-400 text-[11px]">오라클 사건 데이터 검증:</span>
                  <div className="text-emerald-300 font-bold font-mono text-xs flex items-center gap-1">
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>{claimResult.oracle_verification}</span>
                  </div>
                  <p className="text-[10px] text-slate-500">경찰청 ECRM 사건번호 대조 일치</p>
                </div>

                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                  <span className="text-slate-400 text-[11px]">지급 완료 금액:</span>
                  <div className="text-emerald-400 font-black font-mono text-base">
                    {claimResult.payout_amount}
                  </div>
                  <p className="text-[10px] text-slate-500">지정 피해자 계좌로 실시간 송금 완료</p>
                </div>
              </div>

              {/* Transaction Hash with Copy */}
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="flex items-center justify-between text-[11px] text-slate-400 mb-1">
                  <span>온체인 트랜잭션 해시 (EVM Tx Hash):</span>
                  <button
                    onClick={() => copyTx(claimResult.tx_hash)}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[10px]"
                  >
                    {copiedTx ? "복사완료!" : "해시 복사"}
                  </button>
                </div>
                <div className="text-[11px] font-mono text-cyan-300 truncate select-all">
                  {claimResult.tx_hash}
                </div>
              </div>

              <div className="p-2.5 rounded-xl bg-emerald-950/30 border border-emerald-500/30 text-center text-xs font-medium text-emerald-200">
                ✨ {claimResult.message}
              </div>
            </div>
          )}

          {/* Navigation link to On-Chain ledger */}
          {onNavigateToTab && (
            <div className="flex justify-end pt-1">
              <button
                onClick={() => onNavigateToTab('onchain-ledger')}
                className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 transition-colors"
              >
                <span>4번 Web3 멀티시그 온체인 원장에서 트랜잭션 검증하기</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

        </div>

      </div>

    </div>
  );
}
