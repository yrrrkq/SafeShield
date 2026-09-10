"""
SafeShield AI Text Classifier
==============================
This module performs GENUINE LLM-based phishing/smishing content
classification using Anthropic's Claude API — it actually sends the real
text the sandbox extracted (page DOM text + SMS text) to a real model and
uses its real judgment, rather than only counting keyword matches.

Requires the ANTHROPIC_API_KEY environment variable to be set. If it is
not set, or the API call fails for any reason (network error, invalid
key, malformed response, etc.), classify_phishing_text() returns
`{"available": False, ...}` — it never fabricates an AI verdict. Callers
(sandbox.py) are expected to fall back to the existing keyword-based
scoring in that case, and to clearly label which method actually produced
the score that was used.
"""

import json
import logging
import os
from typing import Any, Dict

logger = logging.getLogger("safeshield.ai_classifier")

# Model can be overridden via env var without touching code.
_ANTHROPIC_MODEL = os.environ.get("SAFESHIELD_AI_MODEL", "claude-sonnet-4-5-20250929")
_MAX_TEXT_CHARS = 4000  # keep prompts small/cheap/fast for a demo

_client = None
_client_init_attempted = False


def _get_client():
    """Lazily creates (and caches) the Anthropic client. Returns None if the
    API key isn't configured or the SDK isn't installed — callers must
    handle that as "AI unavailable", not as an error."""
    global _client, _client_init_attempted
    if _client_init_attempted:
        return _client
    _client_init_attempted = True

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.info(
            "ANTHROPIC_API_KEY is not set — AI classifier disabled, "
            "SafeShield will fall back to keyword-based NLP scoring."
        )
        return None

    try:
        import anthropic
        _client = anthropic.Anthropic(api_key=api_key)
    except ImportError:
        logger.warning(
            "The `anthropic` package is not installed — AI classifier disabled. "
            "Install it with `pip install anthropic --break-system-packages`."
        )
        _client = None
    except Exception as e:
        logger.warning(f"Failed to initialize Anthropic client: {e}")
        _client = None

    return _client


SYSTEM_PROMPT = (
    "You are the phishing/smishing content classifier inside SafeShield, a "
    "Korean anti-fraud security product. You will be given real webpage "
    "text and/or SMS text that a browser sandbox actually extracted from a "
    "URL a user is checking. Judge ONLY whether the text itself reads as a "
    "phishing / smishing / voice-phishing attempt — for example "
    "impersonating a government agency, police, prosecutor, bank, or "
    "courier company, and/or pressuring the reader to urgently install an "
    "app or click a link. If the text looks like an ordinary, unrelated "
    "webpage, say so plainly.\n\n"
    "Respond with ONLY a single JSON object and nothing else (no markdown "
    "fences, no commentary), matching exactly this schema:\n"
    '{"is_phishing": boolean, "risk_score": integer from 0 to 20, '
    '"confidence": integer from 0 to 100, "reasoning": string in Korean, '
    "at most 2 short sentences}"
)


async def classify_phishing_text(text: str, url: str = "") -> Dict[str, Any]:
    """
    Sends the REAL extracted text to Claude for genuine LLM-based phishing
    classification.

    Returns:
        {"available": False, ...}  — AI could not be used (no key, no SDK,
            network/parse error). Caller must fall back to keyword scoring.
        {"available": True, "is_phishing": bool, "risk_score": int (0-20),
         "confidence": int (0-100), "reasoning": str, "model": str}
            — a genuine model response.
    """
    client = _get_client()
    if client is None:
        return {"available": False, "reason": "NO_API_KEY_OR_SDK"}

    truncated = (text or "").strip()[:_MAX_TEXT_CHARS]
    if not truncated:
        return {"available": False, "reason": "EMPTY_TEXT"}

    user_prompt = f"URL: {url}\n\n실제로 추출된 페이지/SMS 텍스트:\n{truncated}"

    try:
        response = client.messages.create(
            model=_ANTHROPIC_MODEL,
            max_tokens=300,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        raw_text = "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        ).strip()

        # Be tolerant of the model accidentally wrapping the JSON in a
        # markdown fence despite instructions not to.
        if raw_text.startswith("```"):
            raw_text = raw_text.strip("`")
            if raw_text.lower().startswith("json"):
                raw_text = raw_text[4:]
            raw_text = raw_text.strip()

        parsed = json.loads(raw_text)

        risk_score = int(parsed.get("risk_score", 0))
        risk_score = max(0, min(20, risk_score))
        confidence = int(parsed.get("confidence", 0))
        confidence = max(0, min(100, confidence))

        return {
            "available": True,
            "is_phishing": bool(parsed.get("is_phishing", False)),
            "risk_score": risk_score,
            "confidence": confidence,
            "reasoning": str(parsed.get("reasoning", ""))[:500],
            "model": _ANTHROPIC_MODEL,
        }
    except Exception as e:
        logger.warning(f"AI classifier call failed, falling back to keyword scoring: {e}")
        return {"available": False, "reason": "API_CALL_FAILED", "error": str(e)}