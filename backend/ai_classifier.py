"""
SafeShield AI Threat Analyzer
==============================
This module performs GENUINE LLM-based phishing/smishing THREAT ANALYSIS
using Google's Gemini API — not a simple "phishing / not phishing"
classifier, but a structured analyst-style report.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

print("DEBUG API KEY:", "Loaded" if os.getenv("GEMINI_API_KEY") else "None")

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("safeshield.ai_classifier")

# Google API 표준 최신 모델명 적용
_GEMINI_MODEL = os.environ.get("SAFESHIELD_AI_MODEL", "gemini-3.6-flash")
_MAX_TEXT_CHARS = 4000

_client = None
_client_init_attempted = False


def _get_client():
    global _client, _client_init_attempted
    if _client_init_attempted:
        return _client
    _client_init_attempted = True

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logger.info(
            "GEMINI_API_KEY is not set — AI threat analyzer disabled, "
            "SafeShield will fall back to keyword-based NLP scoring."
        )
        return None

    try:
        from google import genai
        _client = genai.Client(api_key=api_key)
    except ImportError:
        logger.warning(
            "The `google-genai` package is not installed — AI analyzer disabled. "
            "Install it with `pip install google-genai`."
        )
        _client = None
    except Exception as e:
        logger.warning(f"Failed to initialize Gemini client: {e}")
        _client = None

    return _client


SYSTEM_PROMPT = (
    "당신은 SafeShield의 AI 위협 분석가입니다. 한국의 스미싱/보이스피싱 방어 "
    "서비스를 위해, 브라우저 샌드박스가 실제로 추출한 텍스트와 실제로 관찰한 "
    "기술적 증거를 종합하여 위협을 분석합니다. 단순히 '피싱이다/아니다'를 "
    "분류하는 것이 아니라, 어떤 공격 기법이 사용되었고 왜 그렇게 판단했는지를 "
    "구체적으로 설명하는 분석 리포트를 작성해야 합니다.\n\n"
    "함께 제공되는 '기술적 증거'(실제 리다이렉트 횟수, 실제로 다운로드된 파일의 "
    "위험 권한 목록 등)는 샌드박스가 실제로 관측한 사실이므로, 텍스트 내용과 "
    "이 기술적 증거가 서로 부합하는지(또는 모순되는지)도 반드시 분석에 "
    "반영하세요. 예를 들어 텍스트는 평범한데 실제로 위험 권한을 요구하는 "
    "APK가 다운로드되었다면 그 자체가 강한 위협 신호입니다.\n\n"
    "오직 아래 JSON 스키마와 정확히 일치하는 단일 JSON 객체만 응답하세요 "
    "(마크다운 코드블록, 설명, 다른 텍스트 일절 금지):\n"
    "{\n"
    '  "is_phishing": boolean,\n'
    '  "phishing_category": string,\n'
    '  "impersonated_entity": string or null,\n'
    '  "social_engineering_tactics": [string],\n'
    '  "technical_correlation": string,\n'
    '  "risk_score": integer,\n'
    '  "confidence": integer,\n'
    '  "recommended_action": string,\n'
    '  "reasoning": string\n'
    "}"
)


def _format_technical_signals(signals: Optional[Dict[str, Any]]) -> str:
    if not signals:
        return "기술적 증거 없음 (페이지 접속 실패 또는 관측된 신호 없음)"

    parts: List[str] = []
    redirect_count = signals.get("redirect_count", 0)
    parts.append(f"실제 관측된 HTTP 리다이렉트 횟수: {redirect_count}건")

    if signals.get("apk_downloaded"):
        perms = signals.get("detected_permissions") or []
        if perms:
            parts.append(f"실제로 다운로드된 파일에서 발견된 위험 권한: {', '.join(perms)}")
        else:
            parts.append("실제로 파일이 다운로드되었으나 위험 권한은 발견되지 않음")
    else:
        parts.append("실제로 다운로드된 파일 없음")

    if signals.get("institution_cues_detected"):
        parts.append("실제 페이지 DOM에서 기관 사칭 관련 문구가 발견됨")

    return " / ".join(parts)


async def analyze_phishing_threat(
    text: str,
    url: str = "",
    technical_signals: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    client = _get_client()
    if client is None:
        return {"available": False, "reason": "NO_API_KEY_OR_SDK"}

    truncated = (text or "").strip()[:_MAX_TEXT_CHARS]
    if not truncated:
        return {"available": False, "reason": "EMPTY_TEXT"}

    tech_summary = _format_technical_signals(technical_signals)
    user_prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"URL: {url}\n\n"
        f"[실제로 관측된 기술적 증거]\n{tech_summary}\n\n"
        f"[실제로 추출된 페이지/SMS 텍스트]\n{truncated}"
    )

    try:
        response = client.models.generate_content(
            model=_GEMINI_MODEL,
            contents=user_prompt,
        )
        
        raw_text = response.text.strip()

        if raw_text.startswith("```"):
            raw_text = raw_text.strip("`")
            if raw_text.lower().startswith("json"):
                raw_text = raw_text[4:]
            raw_text = raw_text.strip()

        parsed = json.loads(raw_text)

        risk_score = max(0, min(20, int(parsed.get("risk_score", 0))))
        confidence = max(0, min(100, int(parsed.get("confidence", 0))))
        tactics = parsed.get("social_engineering_tactics", [])
        if not isinstance(tactics, list):
            tactics = []

        return {
            "available": True,
            "is_phishing": bool(parsed.get("is_phishing", False)),
            "phishing_category": str(parsed.get("phishing_category", "") or "")[:100],
            "impersonated_entity": (parsed.get("impersonated_entity") or None),
            "social_engineering_tactics": [str(t)[:50] for t in tactics][:10],
            "technical_correlation": str(parsed.get("technical_correlation", ""))[:500],
            "risk_score": risk_score,
            "confidence": confidence,
            "recommended_action": str(parsed.get("recommended_action", ""))[:300],
            "reasoning": str(parsed.get("reasoning", ""))[:800],
            "model": _GEMINI_MODEL,
        }
    except Exception as e:
        logger.warning(f"AI threat analysis call failed, falling back to keyword scoring: {e}")
        return {"available": False, "reason": "API_CALL_FAILED", "error": str(e)}