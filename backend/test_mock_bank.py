import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from mock_bank import MockBankManager

# NOTE: This tests mock_bank.py in isolation. It is a self-contained FAKE
# ledger — nothing here touches a real bank account. The point of this test
# is to prove the lock is *actually enforced in code*, not just a UI label.


def run_tests():
    print("==================================================")
    print("Mock Bank (DEMO virtual account) enforcement test")
    print("==================================================")

    bank = MockBankManager()

    print("\n[1] Initial account status")
    status = bank.get_status("demo-victim-001")
    print(f"  {status}")
    assert status["locked"] is False
    assert status["balance"] == 3_250_000

    print("\n[2] Transfer while UNLOCKED should succeed and actually move balance")
    result = bank.attempt_transfer("demo-victim-001", "demo-attacker-999", 500_000)
    print(f"  {result}")
    assert result["success"] is True
    assert bank.get_status("demo-victim-001")["balance"] == 2_750_000
    assert bank.get_status("demo-attacker-999")["balance"] == 500_000
    print("  [PASS] Balance genuinely moved between demo accounts")

    print("\n[3] Lock the account (simulating a high-risk SafeShield detection)")
    locked_status = bank.lock_account("demo-victim-001", duration_minutes=30, reason="TEST: CRITICAL_MALWARE detected")
    print(f"  {locked_status}")
    assert locked_status["locked"] is True
    assert locked_status["lockRemainingSeconds"] > 0

    print("\n[4] Transfer attempt while LOCKED must be genuinely rejected")
    blocked_result = bank.attempt_transfer("demo-victim-001", "demo-attacker-999", 500_000)
    print(f"  {blocked_result}")
    assert blocked_result["success"] is False
    assert blocked_result["reason"] == "TRANSFER_BLOCKED_BY_ANTI_FRAUD_LOCK"
    # Balance must NOT have changed — this proves the block is real, not cosmetic
    assert bank.get_status("demo-victim-001")["balance"] == 2_750_000
    print("  [PASS] Balance unchanged — the lock genuinely prevented the transfer")

    print("\n[5] Unlock and confirm transfers work again")
    unlocked_status = bank.unlock_account("demo-victim-001")
    print(f"  {unlocked_status}")
    assert unlocked_status["locked"] is False

    result2 = bank.attempt_transfer("demo-victim-001", "demo-attacker-999", 250_000)
    print(f"  {result2}")
    assert result2["success"] is True
    assert bank.get_status("demo-victim-001")["balance"] == 2_500_000
    print("  [PASS] Transfer succeeds again once unlocked")

    print("\n[6] Insufficient balance is genuinely rejected too")
    result3 = bank.attempt_transfer("demo-victim-001", "demo-attacker-999", 99_999_999)
    print(f"  {result3}")
    assert result3["success"] is False
    assert result3["reason"] == "INSUFFICIENT_BALANCE"

    print("\n[7] Unknown demo account raises a clear error")
    try:
        bank.get_status("does-not-exist")
        raise AssertionError("Expected ValueError for unknown account")
    except ValueError as e:
        print(f"  [PASS] {e}")

    print("\n" + "=" * 50)
    print("ALL MOCK BANK TESTS PASSED")
    print("(Reminder: this is a self-contained demo ledger, not a real bank.)")
    print("=" * 50)


if __name__ == "__main__":
    run_tests()