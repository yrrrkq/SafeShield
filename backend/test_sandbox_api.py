import asyncio
import json
import os
import sys

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from main import analyze_sandbox, insurance_claim_demo, SandboxAnalyzeRequest, ClaimDemoRequest
from sandbox import TMP_SANDBOX_DIR

# NOTE: sandbox_engine no longer has a demo/fallback data path. These tests
# hit REAL URLs via Playwright, so assertions here check *structure* and
# *internal consistency* of the response rather than a fixed score that used
# to come from hardcoded fake data (e.g. "threat_score == 96" no longer
# means anything, since it depends on what the live page actually contains).


async def run_all_tests():
    print("==================================================")
    print("Running SafeShield Backend & Sandbox API Test Suite (Real Network)")
    print("==================================================")

    # -------------------------------------------------------------
    # Test 1: POST /api/sandbox/analyze against a real, reachable URL
    # -------------------------------------------------------------
    print("\n[Test 1] Testing /api/sandbox/analyze with a real reachable URL...")
    req = SandboxAnalyzeRequest(
        target_url="https://example.com",
        sms_text="[경찰청] 긴급 압류 통지서 발송. 대출 관련 택배 확인 바랍니다."
    )

    data = await analyze_sandbox(req)
    print("\n--- Sandbox Analyze Response ---")
    print(json.dumps(data, indent=2, ensure_ascii=False))

    # 1. URL echo verification
    assert data["url"] == req.target_url, "URL mismatch"
    print(f"  [PASS] URL echoed correctly: {data['url']}")

    # 2. Reachability verification (example.com must resolve & respond)
    assert data["reachable"] is True, f"Expected example.com to be reachable, got: {data.get('error_detail')}"
    print(f"  [PASS] Target was actually reached by Playwright (reachable=True)")

    # 3. Hash format verification — only meaningful if an APK was actually downloaded.
    # example.com will not serve an APK, so apk_hash should legitimately be None
    # and apk_downloaded should be False. If a hash IS present, it must be well-formed.
    if data["apk_downloaded"]:
        apk_hash = data["apk_hash"]
        assert apk_hash is not None and apk_hash.startswith("0x"), "Hash must start with 0x"
        assert len(apk_hash) == 66, f"EVM bytes32 hash must be 66 characters (0x + 64 hex), got {len(apk_hash)}"
        print(f"  [PASS] Hash format EVM bytes32 verified: {apk_hash}")
    else:
        assert data["apk_hash"] is None, "apk_hash should be None when no APK was actually downloaded"
        print(f"  [PASS] No APK was downloaded from example.com, apk_hash correctly None (no fabricated hash)")

    # 4. AI Analysis structure verification
    ai_analysis = data["ai_analysis"]
    assert "threat_score" in ai_analysis
    assert "confidence_level" in ai_analysis
    assert "verdict" in ai_analysis
    assert "breakdown" in ai_analysis

    breakdown = ai_analysis["breakdown"]
    assert "dynamic_behavior_score" in breakdown
    assert "static_permission_score" in breakdown
    assert "nlp_context_score" in breakdown

    # Internal consistency: total must equal the sum of components (clamped at 100)
    expected_total = min(100, breakdown["dynamic_behavior_score"]
                         + breakdown["static_permission_score"]
                         + breakdown["nlp_context_score"])
    assert ai_analysis["threat_score"] == expected_total, "threat_score must equal sum of breakdown components"
    print(f"  [PASS] threat_score ({ai_analysis['threat_score']}) matches breakdown sum "
          f"(dynamic={breakdown['dynamic_behavior_score']}, static={breakdown['static_permission_score']}, "
          f"nlp={breakdown['nlp_context_score']})")

    # example.com serves no redirect/download/apk, so dynamic & static scores must be 0.
    assert breakdown["dynamic_behavior_score"] == 0, "example.com should not trigger any dynamic behavior signal"
    assert breakdown["static_permission_score"] == 0, "example.com should not yield any static permission score"
    print(f"  [PASS] No fabricated dynamic/static signals present for a benign real page")

    # The SMS text contains real phishing keywords, so NLP score should be > 0.
    assert breakdown["nlp_context_score"] > 0, "Expected NLP score > 0 given phishing-keyword-laden SMS text"
    print(f"  [PASS] NLP score computed from real SMS/page text: {breakdown['nlp_context_score']}"
          f" (matched: {', '.join(ai_analysis.get('matched_keywords', [])) or 'none'})")

    # 5. Permissions verification — must be empty, since no APK was downloaded
    detected_perms = data["detected_permissions"]
    assert isinstance(detected_perms, list)
    if not data["apk_downloaded"]:
        assert detected_perms == [], "detected_permissions must be empty when no APK was downloaded"
    print(f"  [PASS] Detected Permissions: {detected_perms}")

    # 6. Anti-Transfer Lock verification — consistent with the real threat_score
    b2c_actions = data["b2c_actions"]
    anti_transfer = b2c_actions["anti_transfer_lock"]
    expected_locked = ai_analysis["threat_score"] >= 80
    assert anti_transfer["locked"] == expected_locked
    print(f"  [PASS] Anti-Transfer Lock consistent with score: locked={anti_transfer['locked']}")

    # 7. Micro-Insurance Coverage verification
    insurance = b2c_actions["insurance_coverage"]
    expected_pop = "VERIFIED" if ai_analysis["threat_score"] >= 80 else "STANDBY"
    assert insurance["pop_status"] == expected_pop
    assert insurance["max_coverage"] == "3,000,000 KRW"
    print(f"  [PASS] Micro-Insurance PoP Status: {insurance['pop_status']}, Coverage: {insurance['max_coverage']}")

    # 8. Sandbox Isolation verification (strict try-finally cleanup)
    remaining_files = os.listdir(TMP_SANDBOX_DIR)
    assert len(remaining_files) == 0, f"Sandbox folder should be clean, found: {remaining_files}"
    print(f"  [PASS] Sandbox isolation verified: {len(remaining_files)} remaining files in ./tmp_sandbox/")

    # -------------------------------------------------------------
    # Test 2: POST /api/sandbox/analyze against a domain that does not exist
    # -------------------------------------------------------------
    print("\n[Test 2] Testing /api/sandbox/analyze with a non-existent domain (no fake data expected)...")
    req_bad = SandboxAnalyzeRequest(
        target_url="https://this-domain-does-not-exist-safeshield-test-9182.invalid",
        sms_text=None
    )
    data_bad = await analyze_sandbox(req_bad)
    print(json.dumps(data_bad, indent=2, ensure_ascii=False))

    assert data_bad["reachable"] is False, "Non-existent domain must be reported as unreachable"
    assert data_bad["ai_analysis"]["verdict"] == "UNREACHABLE"
    assert data_bad["ai_analysis"]["threat_score"] == 0
    assert data_bad["apk_hash"] is None
    assert data_bad["b2c_actions"]["anti_transfer_lock"]["locked"] is False
    print(f"  [PASS] Unreachable domain correctly yields threat_score=0, verdict=UNREACHABLE, no fabricated lock")

    # -------------------------------------------------------------
    # Test 3: POST /api/insurance/claim-demo
    # -------------------------------------------------------------
    print("\n[Test 3] Testing /api/insurance/claim-demo...")
    claim_req = ClaimDemoRequest(victim_id="victim_citizen_01")
    claim_res = await insurance_claim_demo(claim_req)

    print("\n--- Insurance Claim Demo Response ---")
    print(json.dumps(claim_res, indent=2, ensure_ascii=False))

    assert claim_res["status"] == "SUCCESS"
    assert claim_res["oracle_verification"] == "POLICE_DATA_MATCHED"
    assert claim_res["payout_amount"] == "3,000,000 KRW"
    assert claim_res["tx_hash"].startswith("0x")
    assert len(claim_res["tx_hash"]) == 66
    assert "1.2s" in claim_res["message"]
    print(f"  [PASS] Parametric claim settlement verified. Tx Hash: {claim_res['tx_hash']}")

    print("\n==================================================")
    print("ALL TESTS PASSED (REAL SANDBOX PIPELINE, NO FABRICATED DATA)!")
    print("==================================================")


if __name__ == "__main__":
    asyncio.run(run_all_tests())