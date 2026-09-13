import asyncio
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from analyzer import SandboxAnalyzer
from blockchain import blockchain_manager, ORACLE_NODES

# NOTE: analyzer.py no longer fabricates data. run_sandbox_stream() now drives
# a real Playwright session, so:
#   - a genuinely reachable, benign site (https://example.com) will come back
#     with reachable analysis, sha256 = None (no APK was ever downloaded), and
#     a low riskScore — in which case NOTHING should be registered on-chain.
#   - the on-chain multi-sig pipeline (propose -> endorse -> confirm) is a
#     completely separate concern from the sandbox, so we test it in
#     isolation using an explicit, clearly-labeled mock hash rather than
#     depending on the sandbox having found real malware.


ON_CHAIN_PROPOSAL_THRESHOLD = 70  # mirrors main.py's auto-propose gate


async def test_real_sandbox_pipeline():
    print("==================================================")
    print("[Part 1] Real Sandbox Pipeline Test (https://example.com)")
    print("==================================================")

    analyzer = SandboxAnalyzer()
    test_url = "https://example.com"
    test_sms = "안녕하세요, 요청하신 자료 첨부해서 보내드립니다. 확인 부탁드려요."

    print(f"\n[1] Running real sandbox stream for: {test_url}")
    final_data = None
    async for event in analyzer.run_sandbox_stream(test_url, test_sms):
        print(f"  [{event.get('level', 'INFO')}] {event.get('message')}")
        if event.get("stage") == "RISK_EVALUATION" and "data" in event:
            final_data = event["data"]

    assert final_data is not None, "Final data should not be None"

    print(f"\n[2] Risk Assessment Result:")
    print(f"  Reachable/Verdict: {final_data['verdict']}")
    print(f"  SHA-256: {final_data['sha256']}")
    print(f"  Risk Score: {final_data['riskScore']}/100")
    print(f"  Flagged Permissions: {len(final_data['permissions'])}")

    # A real, reachable benign site must NOT be reported as UNREACHABLE.
    assert final_data["verdict"] != "UNREACHABLE", (
        f"Expected example.com to be reachable, but got verdict={final_data['verdict']} "
        f"(error={final_data.get('error')})"
    )
    print("  [PASS] Target was genuinely reached (verdict is not UNREACHABLE)")

    # example.com serves no APK, so sha256 must legitimately be None.
    assert final_data["sha256"] is None, "sha256 should be None when no APK was actually downloaded"
    print("  [PASS] sha256 correctly None — no APK was downloaded from example.com")

    # No APK => no static permission score => riskScore must stay under the
    # on-chain proposal threshold (max possible without a real APK is 60:
    # 40 dynamic + 20 NLP).
    assert final_data["riskScore"] < ON_CHAIN_PROPOSAL_THRESHOLD, (
        f"Expected riskScore < {ON_CHAIN_PROPOSAL_THRESHOLD} without a real APK, "
        f"got {final_data['riskScore']}"
    )
    print(f"  [PASS] riskScore ({final_data['riskScore']}) is below the on-chain proposal threshold")

    print("\n[3] Verifying that NO on-chain registration is triggered for this result...")
    # This mirrors the exact gate main.py applies before calling propose_threat().
    should_propose = bool(final_data["sha256"]) and final_data["riskScore"] >= ON_CHAIN_PROPOSAL_THRESHOLD
    assert should_propose is False, "A benign, reachable site with no APK must never be proposed on-chain"

    existing_threat = blockchain_manager.get_threat(final_data["sha256"]) if final_data["sha256"] else None
    assert existing_threat is None, "No threat should exist on-chain for a None/absent hash"
    print("  [PASS] On-chain registration correctly skipped (no sha256 / riskScore below threshold)")

    print("\n[SUCCESS] Part 1 (real sandbox pipeline) passed — no fabricated data, no false on-chain registration.")


async def test_blockchain_multisig_pipeline():
    print("\n==================================================")
    print("[Part 2] Blockchain Multi-Sig Pipeline Test (isolated, explicit mock hash)")
    print("==================================================")

    # This hash is explicitly a test fixture, NOT a sandbox result — it exists
    # purely to exercise the on-chain propose/endorse/confirm state machine on
    # its own, independent of whether the sandbox ever finds a real threat.
    mock_apk_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    mock_url = "http://mock-test-fixture.invalid/sample.apk"
    mock_threat_type = "TEST_FIXTURE: Multi-Sig Pipeline Verification"
    mock_permissions = [
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.CALL_PHONE",
        "android.permission.RECORD_AUDIO",
    ]
    mock_threat_score = 95

    print(f"\n[1] Proposing mock threat hash on-chain: {mock_apk_hash}")
    threat = await blockchain_manager.propose_threat(
        apk_hash=mock_apk_hash,
        url=mock_url,
        threat_type=mock_threat_type,
        threat_score=mock_threat_score,
        permissions=mock_permissions,
        proposer_address=ORACLE_NODES[0]["address"]
    )
    print(f"  Proposed by {ORACLE_NODES[0]['name']}")
    print(f"  Status: isConfirmed = {threat['isConfirmed']}, ApprovalCount = {threat['approvalCount']}/2")
    assert threat["isConfirmed"] is False, "Should be pending multi-sig after a single proposal"
    assert threat["approvalCount"] == 1

    print("\n[2] Simulating second oracle node endorsement (AhnLab)...")
    endorsed_threat = await blockchain_manager.endorse_threat(
        apk_hash=mock_apk_hash,
        oracle_address=ORACLE_NODES[1]["address"]
    )
    print(f"  Endorsed by {ORACLE_NODES[1]['name']}")
    print(f"  Status: isConfirmed = {endorsed_threat['isConfirmed']}, ApprovalCount = {endorsed_threat['approvalCount']}/2")
    assert endorsed_threat["isConfirmed"] is True, "Consensus should be reached after 2 endorsements"

    print("\n[3] Verifying on-chain malware lookup...")
    is_blocked = blockchain_manager.is_confirmed(mock_apk_hash)
    print(f"  Is malware confirmed & blocked on-chain: {is_blocked}")
    assert is_blocked is True

    stored_threat = blockchain_manager.get_threat(mock_apk_hash)
    assert stored_threat is not None
    assert stored_threat["threatType"] == mock_threat_type
    assert stored_threat["detectedPermissions"] == mock_permissions
    print("  [PASS] Stored on-chain record matches the proposed mock fixture data")

    print("\n[SUCCESS] Part 2 (blockchain multi-sig pipeline) passed in isolation from sandbox behavior.")


async def run_full_pipeline():
    print("==================================================")
    print("Testing SafeShield Sandbox (real) + Blockchain (isolated) Pipeline")
    print("==================================================")

    await test_real_sandbox_pipeline()
    await test_blockchain_multisig_pipeline()

    print("\n==================================================")
    print("ALL TESTS PASSED SUCCESSFULLY (real sandbox + isolated multi-sig)!")
    print("==================================================")


if __name__ == "__main__":
    asyncio.run(run_full_pipeline())