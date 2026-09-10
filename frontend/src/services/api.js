import { ATTACK_PRESETS, INITIAL_NODES } from "../data/presets";

const BACKEND_URL = "http://localhost:8000";
const WS_URL = "ws://localhost:8000";

/**
 * Checks if the FastAPI backend is running and healthy
 */
export async function checkBackendHealth() {
  try {
    const res = await fetch(`${BACKEND_URL}/`, { method: "GET", signal: AbortSignal.timeout(1200) });
    return res.ok;
  } catch (err) {
    return false;
  }
}

/**
 * Fetches all on-chain threat records from backend (or fallback store)
 */
export async function fetchThreats(status = "all") {
  try {
    const res = await fetch(`${BACKEND_URL}/api/threats?status=${status}`, {
      signal: AbortSignal.timeout(2000)
    });
    if (res.ok) {
      const data = await res.json();
      return data.threats;
    }
  } catch (err) {
    console.warn("Backend not reachable, using local fallback state for threats");
  }
  return null; // Signals fallback to use local state
}

/**
 * Fetches oracle nodes
 */
export async function fetchNodes() {
  try {
    const res = await fetch(`${BACKEND_URL}/api/nodes`, {
      signal: AbortSignal.timeout(2000)
    });
    if (res.ok) {
      const data = await res.json();
      return data.nodes;
    }
  } catch (err) {
    // fallback
  }
  return INITIAL_NODES;
}

/**
 * Runs a REAL sandbox analysis via the backend's Playwright-based engine.
 * POSTs { target_url, sms_text } to /api/sandbox/analyze and returns the
 * raw JSON response — no client-side fabrication happens here or in the
 * caller. Throws on network failure or non-2xx status so the caller can
 * show an honest error instead of silently falling back to fake data.
 */
export async function analyzeUrl(targetUrl, smsText) {
  const res = await fetch(`${BACKEND_URL}/api/sandbox/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target_url: targetUrl,
      sms_text: smsText && smsText.trim().length > 0 ? smsText : null
    }),
    signal: AbortSignal.timeout(30000)
  });

  if (!res.ok) {
    throw new Error(`백엔드가 오류 상태를 반환했습니다 (HTTP ${res.status})`);
  }

  return res.json();
}

/**
 * Endorses a threat on-chain via backend
 */
export async function endorseThreat(apkHash, oracleAddress) {
  try {
    const res = await fetch(`${BACKEND_URL}/api/endorse-threat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apkHash, oracleAddress })
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn("Backend endorse failed, using simulated response");
  }
  return null;
}

/**
 * Opens WebSocket connection for live sandbox streaming
 */
export function createSandboxWebSocket(onMessage, onError, onClose) {
  let ws = null;
  try {
    ws = new WebSocket(`${WS_URL}/ws/sandbox`);
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onMessage(data);
      } catch (e) {
        console.error("WS Parse error", e);
      }
    };
    ws.onerror = (err) => {
      if (onError) onError(err);
    };
    ws.onclose = () => {
      if (onClose) onClose();
    };
  } catch (e) {
    if (onError) onError(e);
  }
  return ws;
}

// =====================================================================
// Mock Bank (demo virtual account) API
// ---------------------------------------------------------------------
// These all talk to /api/mockbank/* on the backend, which operates only
// on an in-memory FAKE ledger (see backend/mock_bank.py). Nothing here
// is connected to any real bank or Open Banking API.
// =====================================================================

/**
 * Fetches the current status (balance, locked, lockRemainingSeconds, ...)
 * of a single demo virtual account.
 */
export async function fetchMockBankAccount(accountNumber) {
  try {
    const res = await fetch(`${BACKEND_URL}/api/mockbank/accounts/${encodeURIComponent(accountNumber)}`, {
      signal: AbortSignal.timeout(3000)
    });
    if (res.ok) {
      const data = await res.json();
      return data.account;
    }
  } catch (err) {
    console.warn("Mock bank account fetch failed", err);
  }
  return null;
}

/**
 * Attempts a (fake) transfer between demo virtual accounts. If the sender
 * account is currently locked, the backend genuinely rejects this — the
 * response's `success` field reflects a real check, not a UI assumption.
 * Throws on network failure so the caller can show an honest error.
 */
export async function attemptMockTransfer(fromAccount, toAccount, amount) {
  const res = await fetch(`${BACKEND_URL}/api/mockbank/transfer`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ from_account: fromAccount, to_account: toAccount, amount }),
    signal: AbortSignal.timeout(5000)
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => null);
    throw new Error((detail && detail.detail) || `백엔드가 오류 상태를 반환했습니다 (HTTP ${res.status})`);
  }
  return res.json();
}

/**
 * Manually locks a demo virtual account — useful for demoing the lock
 * behavior without needing to run a full malicious-URL sandbox analysis.
 */
export async function lockMockAccount(accountNumber, durationMinutes = 30, reason = "Manual lock (demo)") {
  try {
    const res = await fetch(`${BACKEND_URL}/api/mockbank/lock`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ account_number: accountNumber, duration_minutes: durationMinutes, reason }),
      signal: AbortSignal.timeout(3000)
    });
    if (res.ok) {
      const data = await res.json();
      return data.account;
    }
  } catch (err) {
    console.warn("Mock bank lock failed", err);
  }
  return null;
}

/**
 * Manually unlocks a demo virtual account.
 */
export async function unlockMockAccount(accountNumber) {
  try {
    const res = await fetch(`${BACKEND_URL}/api/mockbank/unlock`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ account_number: accountNumber }),
      signal: AbortSignal.timeout(3000)
    });
    if (res.ok) {
      const data = await res.json();
      return data.account;
    }
  } catch (err) {
    console.warn("Mock bank unlock failed", err);
  }
  return null;
}