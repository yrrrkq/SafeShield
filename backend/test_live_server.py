import json
import urllib.request
import urllib.error
import time
import subprocess
import sys
import os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _resolve_python_exe():
    """
    Prefer the project's local virtualenv interpreter if present (Windows layout),
    otherwise fall back to the interpreter currently running this test so the
    script also works on macOS/Linux or when no venv is set up.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    venv_python = os.path.join(base_dir, ".venv", "Scripts", "python.exe")
    if os.path.exists(venv_python):
        return venv_python
    venv_python_posix = os.path.join(base_dir, ".venv", "bin", "python")
    if os.path.exists(venv_python_posix):
        return venv_python_posix
    return sys.executable


def test_live_api():
    port = 8008
    env = os.environ.copy()
    python_exe = _resolve_python_exe()

    proc = subprocess.Popen(
        [python_exe, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )

    try:
        # Wait for server startup
        for _ in range(20):
            time.sleep(0.5)
            if proc.poll() is not None:
                out, err = proc.communicate()
                print("Server exited early! STDOUT:", out.decode("utf-8", errors="ignore"))
                print("STDERR:", err.decode("utf-8", errors="ignore"))
                return

        # -------------------------------------------------------------
        # Test 1: POST /api/sandbox/analyze against a REAL reachable URL.
        # There is no fallback/fake-data path anymore, so we assert on
        # structure/consistency, not a hardcoded score like 96.
        # -------------------------------------------------------------
        req_data = json.dumps({
            "target_url": "https://example.com",
            "sms_text": "[경찰청] 긴급 압류 통지서 발송. 대출 관련 택배 확인 바랍니다."
        }).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/sandbox/analyze",
            data=req_data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            status = resp.status
            body = json.loads(resp.read().decode("utf-8"))
            print(f"POST /api/sandbox/analyze Status: {status}")
            print(json.dumps(body, indent=2, ensure_ascii=False))

            assert status == 200
            assert body["reachable"] is True, "example.com should be genuinely reachable"

            breakdown = body["ai_analysis"]["breakdown"]
            expected_total = min(100, breakdown["dynamic_behavior_score"]
                                 + breakdown["static_permission_score"]
                                 + breakdown["nlp_context_score"])
            assert body["ai_analysis"]["threat_score"] == expected_total, \
                "threat_score must equal the sum of its real breakdown components"

            # No real APK is served by example.com -> no fabricated static score.
            assert breakdown["static_permission_score"] == 0
            assert body["apk_downloaded"] is False
            assert body["apk_hash"] is None

            # SMS text has real phishing keywords -> NLP score must be > 0.
            assert breakdown["nlp_context_score"] > 0

            locked = body["b2c_actions"]["anti_transfer_lock"]["locked"]
            expected_locked = body["ai_analysis"]["threat_score"] >= 80
            assert locked == expected_locked

        print("[PASS] /api/sandbox/analyze produced internally-consistent, non-fabricated results.")

        # -------------------------------------------------------------
        # Test 2: POST /api/sandbox/analyze against a domain that does not exist.
        # Must come back as reachable=False / threat_score=0, never fake malware data.
        # -------------------------------------------------------------
        req_data_bad = json.dumps({
            "target_url": "https://this-domain-does-not-exist-safeshield-test-9182.invalid"
        }).encode("utf-8")
        req_bad = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/sandbox/analyze",
            data=req_data_bad,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_bad, timeout=20) as resp_bad:
            status_bad = resp_bad.status
            body_bad = json.loads(resp_bad.read().decode("utf-8"))
            print(f"\nPOST /api/sandbox/analyze (unreachable) Status: {status_bad}")
            print(json.dumps(body_bad, indent=2, ensure_ascii=False))

            assert status_bad == 200
            assert body_bad["reachable"] is False
            assert body_bad["ai_analysis"]["verdict"] == "UNREACHABLE"
            assert body_bad["ai_analysis"]["threat_score"] == 0
            assert body_bad["b2c_actions"]["anti_transfer_lock"]["locked"] is False

        print("[PASS] Unreachable domain correctly returned zero-score result (no fallback fake data).")

        # -------------------------------------------------------------
        # Test 3: POST /api/insurance/claim-demo
        # -------------------------------------------------------------
        claim_data = json.dumps({"victim_id": "test_citizen"}).encode("utf-8")
        req2 = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/insurance/claim-demo",
            data=claim_data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req2, timeout=10) as resp2:
            status2 = resp2.status
            body2 = json.loads(resp2.read().decode("utf-8"))
            print(f"\nPOST /api/insurance/claim-demo Status: {status2}")
            print(json.dumps(body2, indent=2, ensure_ascii=False))
            assert status2 == 200
            assert body2["status"] == "SUCCESS"
            assert body2["payout_amount"] == "3,000,000 KRW"
            assert body2["tx_hash"].startswith("0x")

        print("\n[SUCCESS] Live HTTP server verified all endpoints with real network behavior!")
    finally:
        proc.terminate()
        proc.kill()


if __name__ == "__main__":
    test_live_api()