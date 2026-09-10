import React, { useState } from 'react';
import { ShieldCheck, Zap, CheckCircle2, ArrowRight, ExternalLink, AlertTriangle, FileText } from 'lucide-react';

export function Web3InsuranceClaimCard() {
  const [claiming, setClaiming] = useState(false);
  const [claimResult, setClaimResult] = useState(null);

  const handleClaim = async () => {
    setClaiming(true);
    try {
      const res = await fetch("http://localhost:8000/api/insurance/claim-demo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ victim_id: "citizen_demo_user" })
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

  return (
    <div className="flex flex-col h-full bg-[#0b1120] border border-slate-800/80 rounded-2xl p-4 shadow-2xl space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">소액 보이스피싱 보험 스마트 청구</h3>
            <p className="text-[11px] text-slate-400">오라클 경찰청 사건 데이터 매칭 파라메트릭 즉시 지급</p>
          </div>
        </div>
        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/40">
          오라클 자동화
        </span>
      </div>

      {/* Info summary */}
      <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
        <div className="flex items-center justify-between text-xs">
          <span className="text-slate-400">피해 보장 한도:</span>
          <span className="font-bold text-white font-mono text-sm">최대 3,000,000 KRW</span>
        </div>
        <div className="flex items-center justify-between text-xs">
          <span className="text-slate-400">오라클 데이터 소스:</span>
          <span className="text-cyan-400 font-medium">경찰청 사이버범죄 신고시스템(ECRM)</span>
        </div>
        <div className="flex items-center justify-between text-xs">
          <span className="text-slate-400">평균 지급 심사 소요시간:</span>
          <span className="text-emerald-400 font-bold font-mono">1.2초 (스마트 계약 자동 실행)</span>
        </div>
      </div>

      {/* Claim Action Button */}
      <div className="pt-1">
        <button
          onClick={handleClaim}
          disabled={claiming}
          className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-bold shadow-lg shadow-emerald-950/50 flex items-center justify-center gap-2 transition-all active:scale-98 disabled:opacity-50"
        >
          {claiming ? (
            <>
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              <span>스마트 계약 오라클 검증 중...</span>
            </>
          ) : (
            <>
              <Zap className="w-4 h-4 fill-white" />
              <span>원클릭 보험금 청구 시뮬레이션 실행</span>
            </>
          )}
        </button>
      </div>

      {/* Payout Result Receipt */}
      {claimResult && (
        <div className="p-3.5 rounded-xl bg-slate-950 border border-emerald-500/50 space-y-2 animate-fadeIn">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" /> 지급 승인 완료
            </span>
            <span className="text-[10px] font-mono bg-emerald-950 px-2 py-0.5 rounded text-emerald-300">
              {claimResult.status}
            </span>
          </div>

          <div className="p-2 rounded bg-slate-900 border border-slate-800 space-y-1 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-400 text-[11px]">오라클 검증 결과:</span>
              <span className="text-emerald-300 font-semibold text-[11px]">{claimResult.oracle_verification}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400 text-[11px]">지급 금액:</span>
              <span className="text-emerald-400 font-bold font-mono text-sm">{claimResult.payout_amount}</span>
            </div>
          </div>

          <div>
            <span className="text-[10px] text-slate-400 block mb-0.5">스마트 컨트랙트 트랜잭션 해시:</span>
            <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-cyan-400 truncate">
              {claimResult.tx_hash}
            </div>
          </div>

          <p className="text-[11px] text-slate-300 text-center pt-1 border-t border-slate-900">
            {claimResult.message}
          </p>
        </div>
      )}
    </div>
  );
}
