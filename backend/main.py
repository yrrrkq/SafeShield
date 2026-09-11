import asyncio
import json
import sys
import time
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import os
from dotenv import load_dotenv

# 백엔드 실행 시 .env 파일 로드
load_dotenv()
# -----------------------------------------------------------------------
# Windows + Playwright fix: on Windows, asyncio's default SelectorEventLoop
# cannot spawn subprocesses (Playwright launches the browser as a real
# subprocess), which raises `NotImplementedError` deep inside Playwright.
# uvicorn's `--reload` mode in particular tends to end up on the Selector
# loop on Windows, so we explicitly force the Proactor policy here, before
# anything else creates an event loop. This is a no-op on Linux/macOS.
# -----------------------------------------------------------------------
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from analyzer import SandboxAnalyzer
from sandbox import sandbox_engine
from blockchain import blockchain_manager, ORACLE_NODES
from mock_bank import mock_bank_manager

app = FastAPI(
    title="SafeShield AI Sandbox & Web3 Oracle Backend",
    description="Real-time smishing and voice phishing defense system with multi-sig oracle consensus.",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

analyzer = SandboxAnalyzer()

# Pydantic Schemas
class SandboxAnalyzeRequest(BaseModel):
    target_url: Optional[str] = None
    url: Optional[str] = None
    sms_text: Optional[str] = None
    account_number: Optional[str] = None  # which DEMO virtual account to protect/lock

class ClaimDemoRequest(BaseModel):
    victim_id: Optional[str] = "victim_citizen_01"
    threat_hash: Optional[str] = None
    claim_reason: Optional[str] = "Smishing Wiretap Unauthorized Transfer"

class MockTransferRequest(BaseModel):
    from_account: str = "demo-victim-001"
    to_account: str
    amount: float = Field(gt=0)

class MockLockRequest(BaseModel):
    account_number: str = "demo-victim-001"
    duration_minutes: int = Field(default=30, ge=1, le=1440)
    reason: Optional[str] = "Manual lock (demo)"

class MockUnlockRequest(BaseModel):
    account_number: str = "demo-victim-001"

class AnalyzeRequest(BaseModel):
    url: str
    sms_text: Optional[str] = None
    auto_propose: bool = True
    auto_consensus: bool = True

class ProposeThreatRequest(BaseModel):
    apkHash: str
    url: str
    threatType: str
    threatScore: int = Field(ge=0, le=100)
    permissions: List[str]
    proposerAddress: Optional[str] = None

class EndorseThreatRequest(BaseModel):
    apkHash: str
    oracleAddress: str

@app.get("/")
async def root():
    return {
        "service": "SafeShield AI Sandbox & Web3 Oracle",
        "status": "OPERATIONAL",
        "version": "1.0.0",
        "blockchain": {
            "network": "SafeShield EVM Subnet / Sepolia",
            "contract": blockchain_manager.contract_address,
            "blockHeight": blockchain_manager.block_height,
            "requiredSignatures": blockchain_manager.required_signatures
        }
    }

@app.get("/api/nodes")
async def get_nodes():
    return {
        "success": True,
        "nodes": ORACLE_NODES,
        "requiredSignatures": blockchain_manager.required_signatures,
        "totalNodes": len(ORACLE_NODES)
    }

@app.get("/api/threats")
async def get_threats(status: str = Query("all", pattern="^(all|confirmed|pending)$")):
    threats = blockchain_manager.get_all_threats()
    if status == "confirmed":
        threats = [t for t in threats if t.get("isConfirmed")]
    elif status == "pending":
        threats = [t for t in threats if not t.get("isConfirmed") and not t.get("isRevoked")]
    
    # Sort latest first
    threats.sort(key=lambda x: x.get("proposedAt", 0), reverse=True)
    return {
        "success": True,
        "count": len(threats),
        "threats": threats
    }

@app.get("/api/threats/{apk_hash}")
async def get_threat_detail(apk_hash: str):
    threat = blockchain_manager.get_threat(apk_hash)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat hash not found in on-chain registry")
    return {"success": True, "threat": threat}

@app.get("/api/verify-hash/{apk_hash}")
async def verify_hash(apk_hash: str):
    is_malware = blockchain_manager.is_confirmed(apk_hash)
    threat = blockchain_manager.get_threat(apk_hash)
    return {
        "apkHash": apk_hash,
        "isBlocked": is_malware,
        "status": "BLOCKED_ON_CHAIN" if is_malware else ("PENDING_CONSENSUS" if threat else "CLEAN_OR_UNKNOWN"),
        "threatScore": threat["threatScore"] if threat else 0,
        "threatType": threat["threatType"] if threat else None
    }

@app.get("/api/stats")
async def get_stats():
    threats = blockchain_manager.get_all_threats()
    confirmed = [t for t in threats if t.get("isConfirmed")]
    pending = [t for t in threats if not t.get("isConfirmed") and not t.get("isRevoked")]
    
    return {
        "totalThreats": len(threats),
        "confirmedBlocked": len(confirmed),
        "pendingConsensus": len(pending),
        "blockHeight": blockchain_manager.block_height,
        "oracleNodesOnline": len(ORACLE_NODES),
        "averageConsensusTimeSec": 1.8,
        "contractAddress": blockchain_manager.contract_address
    }

@app.post("/api/propose-threat")
async def propose_threat(req: ProposeThreatRequest):
    try:
        threat = await blockchain_manager.propose_threat(
            apk_hash=req.apkHash,
            url=req.url,
            threat_type=req.threatType,
            threat_score=req.threatScore,
            permissions=req.permissions,
            proposer_address=req.proposerAddress
        )
        return {"success": True, "threat": threat}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/endorse-threat")
async def endorse_threat(req: EndorseThreatRequest):
    try:
        threat = await blockchain_manager.endorse_threat(
            apk_hash=req.apkHash,
            oracle_address=req.oracleAddress
        )
        return {"success": True, "threat": threat}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/analyze-url")
async def analyze_url(req: AnalyzeRequest):
    """
    Synchronous / Polling endpoint for analyzing a URL and auto-triggering on-chain consensus.
    """
    events = []
    final_data = None
    
    async for event in analyzer.run_sandbox_stream(req.url, req.sms_text):
        events.append(event)
        if event.get("stage") == "RISK_EVALUATION" and "data" in event:
            final_data = event["data"]

    if not final_data:
        raise HTTPException(status_code=500, detail="Sandbox execution failed to produce risk assessment")

    # If score high and auto_propose enabled -> Propose on-chain
    threat_entry = None
    if req.auto_propose and final_data["riskScore"] >= 70:
        threat_entry = await blockchain_manager.propose_threat(
            apk_hash=final_data["sha256"],
            url=req.url,
            threat_type=final_data["threatType"],
            threat_score=final_data["riskScore"],
            permissions=[p["permission"] for p in final_data["permissions"]],
            proposer_address=ORACLE_NODES[0]["address"]
        )

        if req.auto_consensus:
            # Trigger background consensus signatures from other nodes
            asyncio.create_task(blockchain_manager.auto_multi_sig_pipeline(final_data["sha256"], delay_seconds=1.2))

    return {
        "success": True,
        "analysis": final_data,
        "logs": events,
        "onChainThreat": threat_entry
    }

@app.api_route("/api/sandbox/analyze", methods=["GET", "POST"])
async def analyze_sandbox(
    req: Optional[SandboxAnalyzeRequest] = None,
    target_url: Optional[str] = Query(None, description="Target URL if calling via GET query param"),
    account_number: Optional[str] = Query(None, description="DEMO virtual account number to protect/lock")
):
    """
    SafeShield AI Sandbox Analysis Endpoint (Supports both POST body and GET query param):
    - Launches isolated Chromium sandbox with Playwright
    - Detects HTTP redirects, deceptive DOM, and automatic .apk downloads
    - Generates 0x-prefixed SHA-256 hash (bytes32 EVM compatible)
    - Enforces strict try-finally cleanup (os.remove) to isolate environment
    - Computes hybrid threat score (Dynamic 40 + Static 40 + NLP 20 = 100)
    - Triggers B2C protections: Anti-Transfer Lock (against a DEMO virtual
      account in mock_bank.py — NOT a real bank account) & Web3 Micro-Insurance
    """
    target = None
    sms_text = None
    account_no = None
    if req:
        target = req.target_url or req.url
        sms_text = req.sms_text
        account_no = req.account_number
    if not target:
        target = target_url
    if not target:
        target = "[http://police-cyber-bureau.kr/emergency_warrant.apk](http://police-cyber-bureau.kr/emergency_warrant.apk)"
    if not account_no:
        account_no = account_number
    if not account_no:
        account_no = "demo-victim-001"

    result = await sandbox_engine.inspect_url(target_url=target, sms_text=sms_text)

    # -------------------------------------------------------------
    # DEMO Anti-Transfer Lock: really locks a DEMO virtual account
    # (mock_bank.py) when the threat score is high — this is NOT a real
    # bank account and NOT connected to any Open Banking / core-banking
    # system. It exists so the "lock" can be demonstrated as something
    # that genuinely blocks a (fake) transfer, rather than a UI label only.
    # -------------------------------------------------------------
    try:
        was_locked_before = mock_bank_manager.is_locked(account_no)
    except ValueError:
        was_locked_before = False

    try:
        should_lock = result.get("reachable") and result["ai_analysis"]["threat_score"] >= 80
        if should_lock:
            bank_status = mock_bank_manager.lock_account(
                account_no,
                duration_minutes=30,
                reason=(
                    f"SafeShield 탐지: {result['ai_analysis']['verdict']} "
                    f"(threat_score={result['ai_analysis']['threat_score']}, url={target})"
                )
            )
        else:
            bank_status = mock_bank_manager.get_status(account_no)

        result.setdefault("b2c_actions", {}).setdefault("anti_transfer_lock", {})
        result["b2c_actions"]["anti_transfer_lock"]["locked"] = bank_status["locked"]
        # True only when THIS request is what just triggered the lock — lets the
        # frontend distinguish "newly locked just now" from "still locked from an
        # earlier, unrelated check," instead of both looking identical.
        result["b2c_actions"]["anti_transfer_lock"]["justLocked"] = bool(should_lock and not was_locked_before)
        result["b2c_actions"]["anti_transfer_lock"]["lock_duration_minutes"] = 30 if bank_status["locked"] else 0
        result["b2c_actions"]["anti_transfer_lock"]["message"] = (
            f"CRITICAL THREAT DETECTED: Demo Virtual Account Transfers Frozen for 30 Minutes"
            if bank_status["locked"] else
            "Transfers permitted: threat score within safe threshold (demo virtual account)."
        )
        result["b2c_actions"]["anti_transfer_lock"]["demoAccount"] = bank_status
        result["b2c_actions"]["anti_transfer_lock"]["isRealBankAccount"] = False
    except ValueError as e:
        # Unknown demo account number — surface as a normal (non-fatal)
        # detail rather than crashing the analysis response.
        result.setdefault("b2c_actions", {}).setdefault("anti_transfer_lock", {})
        result["b2c_actions"]["anti_transfer_lock"]["error"] = str(e)

    # Automatically register to on-chain threat registry if critical malware.
    # NOTE: sandbox_engine no longer fabricates data. If the target was
    # unreachable, or no APK was actually downloaded, apk_hash will be None
    # and there is nothing legitimate to register on-chain, so we skip.
    if result.get("reachable") and result["ai_analysis"]["threat_score"] >= 80:
        apk_hash = result.get("apk_hash")
        if apk_hash:
            try:
                if not blockchain_manager.get_threat(apk_hash):
                    matched_kw = result["ai_analysis"].get("matched_keywords") or []
                    threat_type = (
                        f"Smishing/Phishing Trojan ({', '.join(matched_kw)})"
                        if matched_kw else "Smishing Trojan Dropper"
                    )
                    await blockchain_manager.propose_threat(
                        apk_hash=apk_hash,
                        url=target,
                        threat_type=threat_type,
                        threat_score=result["ai_analysis"]["threat_score"],
                        permissions=[f"android.permission.{p}" for p in result["detected_permissions"]],
                        proposer_address=ORACLE_NODES[0]["address"]
                    )
            except Exception:
                pass

    return result

# =====================================================================
# DEMO Mock Bank Endpoints
# ---------------------------------------------------------------------
# These operate ONLY on the in-memory virtual accounts defined in
# mock_bank.py. They are not connected to any real bank, card network,
# or Open Banking API — this is explicitly a self-contained demo ledger
# so the "anti-transfer lock" can be shown actually blocking a transfer,
# rather than only toggling a UI label.
# =====================================================================

@app.get("/api/mockbank/accounts")
async def mockbank_list_accounts():
    return {"success": True, "isRealBank": False, "accounts": mock_bank_manager.list_accounts()}

@app.get("/api/mockbank/accounts/{account_number}")
async def mockbank_account_status(account_number: str):
    try:
        return {"success": True, "isRealBank": False, "account": mock_bank_manager.get_status(account_number)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/mockbank/transfer")
async def mockbank_transfer(req: MockTransferRequest):
    """
    Attempts a (fake) transfer between demo virtual accounts. If the
    sender account is currently locked (e.g. because /api/sandbox/analyze
    just flagged a high threat score), this genuinely rejects the
    transfer — the check happens inside mock_bank.attempt_transfer(),
    not in the frontend.
    """
    try:
        result = mock_bank_manager.attempt_transfer(req.from_account, req.to_account, req.amount)
        result["isRealBank"] = False
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/mockbank/lock")
async def mockbank_lock(req: MockLockRequest):
    """Manually lock a demo virtual account (useful for testing the lock
    behavior independent of running a full sandbox analysis)."""
    try:
        status = mock_bank_manager.lock_account(req.account_number, req.duration_minutes, req.reason)
        return {"success": True, "isRealBank": False, "account": status}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/mockbank/unlock")
async def mockbank_unlock(req: MockUnlockRequest):
    try:
        status = mock_bank_manager.unlock_account(req.account_number)
        return {"success": True, "isRealBank": False, "account": status}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/mockbank/transfers")
async def mockbank_transfer_log(account_number: Optional[str] = Query(None)):
    return {
        "success": True,
        "isRealBank": False,
        "transfers": mock_bank_manager.get_transfer_log(account_number)
    }

@app.api_route("/api/insurance/claim-demo", methods=["GET", "POST"])
async def insurance_claim_demo(req: Optional[ClaimDemoRequest] = None):
    """
    B2C Web3 Micro-Insurance Parametric Auto-Payout Endpoint (Supports both GET and POST):
    Simulates instantaneous smart contract claim settlement and payout when triggered.
    """
    # Deterministic or mock EVM transaction hash conforming to 64 hex chars
    tx_hash = "0xabc1234567890def1234567890def1234567890def1234567890def123456789"
    return {
        "status": "SUCCESS",
        "oracle_verification": "POLICE_DATA_MATCHED",
        "payout_amount": "3,000,000 KRW",
        "tx_hash": tx_hash,
        "message": "Parametric Insurance Payout Approved & Sent in 1.2s"
    }

@app.websocket("/ws/sandbox")
async def websocket_sandbox_stream(websocket: WebSocket):
    """
    Real-time interactive WebSocket stream: Client sends URL, server streams terminal logs line-by-line.
    """
    await websocket.accept()
    try:
        while True:
            raw_msg = await websocket.receive_text()
            data = json.loads(raw_msg)
            
            action = data.get("action")
            if action == "analyze":
                target_url = data.get("url", "[http://malicious-node.xyz/update.apk](http://malicious-node.xyz/update.apk)")
                sms_text = data.get("sms_text", "")
                auto_propose = data.get("auto_propose", True)
                auto_consensus = data.get("auto_consensus", True)

                # Send initial start event
                await websocket.send_json({
                    "event": "SANDBOX_START",
                    "targetUrl": target_url,
                    "timestamp": time.strftime("%H:%M:%S")
                })

                final_assessment = None

                async for log_event in analyzer.run_sandbox_stream(target_url, sms_text):
                    await websocket.send_json({
                        "event": "LOG_ENTRY",
                        "log": log_event
                    })
                    if log_event.get("stage") == "RISK_EVALUATION" and "data" in log_event:
                        final_assessment = log_event["data"]

                if final_assessment and auto_propose and final_assessment["riskScore"] >= 70:
                    apk_hash = final_assessment["sha256"]
                    
                    # Propose to contract
                    threat_entry = await blockchain_manager.propose_threat(
                        apk_hash=apk_hash,
                        url=target_url,
                        threat_type=final_assessment["threatType"],
                        threat_score=final_assessment["riskScore"],
                        permissions=[p["permission"] for p in final_assessment["permissions"]],
                        proposer_address=ORACLE_NODES[0]["address"]
                    )

                    await websocket.send_json({
                        "event": "THREAT_PROPOSED",
                        "threat": threat_entry
                    })

                    if auto_consensus:
                        # Stream Node 2 signature after 1s
                        await asyncio.sleep(1.2)
                        threat_entry = await blockchain_manager.endorse_threat(
                            apk_hash=apk_hash,
                            oracle_address=ORACLE_NODES[1]["address"]
                        )
                        await websocket.send_json({
                            "event": "THREAT_ENDORSED",
                            "node": ORACLE_NODES[1]["name"],
                            "threat": threat_entry
                        })

                        # Stream Node 3 signature after another 1s
                        await asyncio.sleep(1.0)
                        threat_entry = await blockchain_manager.endorse_threat(
                            apk_hash=apk_hash,
                            oracle_address=ORACLE_NODES[2]["address"]
                        )
                        await websocket.send_json({
                            "event": "THREAT_CONFIRMED",
                            "threat": threat_entry
                        })

                await websocket.send_json({
                    "event": "SANDBOX_COMPLETE",
                    "timestamp": time.strftime("%H:%M:%S")
                })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"event": "ERROR", "message": str(e)})
        except Exception:
            pass

@app.websocket("/ws/broadcast")
async def websocket_global_broadcast(websocket: WebSocket):
    """
    WebSocket channel for receiving live global blockchain broadcasts (MalwareConfirmed events)
    """
    await websocket.accept()
    queue = await blockchain_manager.subscribe()
    try:
        while True:
            msg = await queue.get()
            await websocket.send_json(msg)
    except WebSocketDisconnect:
        blockchain_manager.unsubscribe(queue)
    except Exception:
        blockchain_manager.unsubscribe(queue)

if __name__ == "__main__":
    import uvicorn
    # IMPORTANT: reload=False on purpose. uvicorn's --reload/StatReload
    # supervisor overrides the Windows event loop policy we set at the top
    # of this file, which breaks Playwright's ability to launch a browser
    # subprocess (raises NotImplementedError deep inside Playwright). If
    # you need auto-reload during development on Windows, restart the
    # server manually after each change instead of using --reload.
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)