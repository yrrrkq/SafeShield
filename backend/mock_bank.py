import time
from typing import Any, Dict, List, Optional

# =====================================================================
# MockBankManager
# ---------------------------------------------------------------------
# This is a SELF-CONTAINED, IN-MEMORY, FAKE banking ledger used only for
# demo purposes. It is intentionally NOT connected to any real bank,
# Open Banking API, card network, or PG. There is no code anywhere in
# this module that reaches out to an external financial institution.
#
# What it DOES do, for real (within its own fake ledger):
#   - Tracks demo account balances.
#   - When SafeShield's sandbox analysis flags a target as high-risk, the
#     backend calls lock_account() on a demo account, which sets a real
#     locked_until timestamp.
#   - attempt_transfer() actually checks that timestamp and genuinely
#     REJECTS a (fake) transfer while the lock is active — this is not a
#     UI-only flag, the block is enforced in this function's own logic.
#
# What it explicitly does NOT do:
#   - It never touches a real bank account balance.
#   - It cannot lock, freeze, or otherwise affect any real financial
#     account. Doing that requires a formal Open Banking / core-banking
#     integration and legal/regulatory clearance that this project does
#     not have.
# =====================================================================


class MockBankManager:
    def __init__(self):
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.transfer_log: List[Dict[str, Any]] = []
        self._seed_demo_accounts()

    def _seed_demo_accounts(self):
        self.accounts["demo-victim-001"] = {
            "account_number": "demo-victim-001",
            "owner_name": "김민준 (데모 피해자 가상계좌)",
            "balance": 3_250_000,
            "currency": "KRW",
            "locked_until": None,
            "lock_reason": None,
        }
        self.accounts["demo-attacker-999"] = {
            "account_number": "demo-attacker-999",
            "owner_name": "알 수 없는 수취인 (데모 사기범 가상계좌)",
            "balance": 0,
            "currency": "KRW",
            "locked_until": None,
            "lock_reason": None,
        }

    # -----------------------------------------------------------------
    def _get_or_error(self, account_number: str) -> Dict[str, Any]:
        if account_number not in self.accounts:
            raise ValueError(f"존재하지 않는 데모 가상계좌입니다: {account_number}")
        return self.accounts[account_number]

    def _ensure_account(self, account_number: str, owner_name: str = "외부 데모 가상계좌") -> Dict[str, Any]:
        """Creates a zero-balance demo account on the fly if it doesn't exist yet,
        so transfer testing between arbitrary demo account numbers works without
        requiring every account to be pre-seeded."""
        if account_number not in self.accounts:
            self.accounts[account_number] = {
                "account_number": account_number,
                "owner_name": owner_name,
                "balance": 0,
                "currency": "KRW",
                "locked_until": None,
                "lock_reason": None,
            }
        return self.accounts[account_number]

    # -----------------------------------------------------------------
    def is_locked(self, account_number: str) -> bool:
        account = self._get_or_error(account_number)
        locked_until = account.get("locked_until")
        return locked_until is not None and locked_until > time.time()

    def lock_account(self, account_number: str, duration_minutes: int, reason: str) -> Dict[str, Any]:
        """Really sets a lock — attempt_transfer() below will genuinely
        honor this and reject transfers until it expires."""
        account = self._get_or_error(account_number)
        account["locked_until"] = time.time() + max(0, duration_minutes) * 60
        account["lock_reason"] = reason
        return self.get_status(account_number)

    def unlock_account(self, account_number: str) -> Dict[str, Any]:
        account = self._get_or_error(account_number)
        account["locked_until"] = None
        account["lock_reason"] = None
        return self.get_status(account_number)

    def get_status(self, account_number: str) -> Dict[str, Any]:
        account = self._get_or_error(account_number)
        locked = self.is_locked(account_number)
        remaining = 0
        if locked:
            remaining = max(0, int(account["locked_until"] - time.time()))
        return {
            "accountNumber": account["account_number"],
            "ownerName": account["owner_name"],
            "balance": account["balance"],
            "currency": account["currency"],
            "locked": locked,
            "lockRemainingSeconds": remaining,
            "lockReason": account["lock_reason"] if locked else None,
        }

    def list_accounts(self) -> List[Dict[str, Any]]:
        return [self.get_status(acc) for acc in self.accounts.keys()]

    # -----------------------------------------------------------------
    def attempt_transfer(self, from_account: str, to_account: str, amount: float) -> Dict[str, Any]:
        """
        Genuinely enforces the lock: if the sender's demo account is
        currently locked, the transfer is rejected right here — this is
        real control flow, not a cosmetic flag the UI happens to check.
        """
        if amount <= 0:
            return {
                "success": False,
                "reason": "INVALID_AMOUNT",
                "message": "이체 금액은 0보다 커야 합니다.",
                "account": self.get_status(from_account) if from_account in self.accounts else None,
            }

        sender = self._get_or_error(from_account)
        recipient = self._ensure_account(to_account)

        if self.is_locked(from_account):
            status = self.get_status(from_account)
            return {
                "success": False,
                "reason": "TRANSFER_BLOCKED_BY_ANTI_FRAUD_LOCK",
                "message": (
                    f"이 데모 가상계좌는 SafeShield 스미싱/악성코드 탐지로 인해 잠금 상태입니다. "
                    f"약 {status['lockRemainingSeconds']}초 후 다시 시도해주세요."
                ),
                "account": status,
            }

        if sender["balance"] < amount:
            return {
                "success": False,
                "reason": "INSUFFICIENT_BALANCE",
                "message": "잔액이 부족합니다.",
                "account": self.get_status(from_account),
            }

        sender["balance"] -= amount
        recipient["balance"] += amount
        record = {
            "from": from_account,
            "to": to_account,
            "amount": amount,
            "timestamp": int(time.time()),
        }
        self.transfer_log.append(record)

        return {
            "success": True,
            "reason": None,
            "message": "이체가 완료되었습니다. (데모 가상계좌 간 이체 — 실제 은행 거래 아님)",
            "account": self.get_status(from_account),
            "transfer": record,
        }

    def get_transfer_log(self, account_number: Optional[str] = None) -> List[Dict[str, Any]]:
        if not account_number:
            return list(self.transfer_log)
        return [t for t in self.transfer_log if t["from"] == account_number or t["to"] == account_number]


# Global singleton instance, mirroring the style of blockchain_manager/sandbox_engine
mock_bank_manager = MockBankManager()