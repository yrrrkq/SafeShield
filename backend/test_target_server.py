"""
SafeShield DEMO Test Target Server
===================================

THIS IS NOT A REAL PHISHING SITE, AND NONE OF THE "APK" FILES IT SERVES ARE
REAL MALWARE. This is a small, self-hosted, harmless test fixture whose
only purpose is to let SafeShield's real Playwright-based sandbox pipeline
(page load -> HTTP redirect -> auto file "download" -> static permission
parsing -> hybrid scoring -> demo anti-transfer lock) run end-to-end
against something you control, instead of needing an actual live phishing
page.

Why this is safe:
  - Every "*.apk" served here is a plain ZIP archive that contains only a
    text AndroidManifest.xml file. None of them have classes.dex, native
    code, or any executable logic — Android itself would refuse to install
    them. They exist purely so SafeShield's static analyzer (zipfile +
    manifest text scan) has a real file to open.
  - Every landing page is static HTML/JS that only performs a same-origin
    redirect and a same-origin "download" navigation — no exploitation,
    no touching the visitor's device, no data exfiltration anywhere.

Four themed scenarios are served, matching the four preset buttons in the
SafeShield demo UI (택배 스미싱 / 청첩장 스미싱 / 대출 피싱 / 경찰 사칭):

    http://127.0.0.1:9100/parcel
    http://127.0.0.1:9100/wedding
    http://127.0.0.1:9100/loan
    http://127.0.0.1:9100/police

The original root URL (http://127.0.0.1:9100/) still works exactly as
before (it's an alias for the "police" scenario), so any earlier demo
recording or bookmark keeps working.

How to run it:
    pip install fastapi uvicorn --break-system-packages
    python test_target_server.py
    # Serves on http://127.0.0.1:9100/

Then paste one of the scenario URLs above into the SafeShield frontend's
"Malicious URL" (Custom URL) field and run the analysis. Because these
targets are genuinely reachable, SafeShield's real sandbox will actually
observe an HTTP redirect, actually download the fixture .apk, actually
parse its manifest for dangerous permission strings, actually compute a
real hybrid threat score, and (once that score clears 80) will actually
call mock_bank.py to lock the demo virtual account and reject a demo
transfer — nothing in this chain is fabricated by the server itself; the
SERVER is the only thing that's fake, everything SafeShield does with it
afterward is real.
"""

import io
import zipfile
from typing import Dict

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI(title="SafeShield DEMO Test Target (NOT a real phishing site)")

# -----------------------------------------------------------------------
# Scenario definitions — one per preset button in the demo UI.
# `permissions` lists the manifest permission strings that will actually
# be embedded in that scenario's fixture .apk (varies on purpose, so the
# static-permission score genuinely differs by scenario instead of always
# maxing out).
# -----------------------------------------------------------------------

SCENARIOS: Dict[str, Dict[str, str]] = {
    "parcel": {
        "title": "[CJ대한통운] 배송 주소 불일치 확인",
        "body_html": """
            <h1>[CJ대한통운] 고객님의 택배가 배송 보류 중입니다</h1>
            <p>도로명 주소 불일치로 택배가 배송 보류 상태입니다. 재배송을 위해
               아래 배송지 확인 앱(APK)을 설치해 주세요.</p>
            <p>택배 조회번호: 5829-4471-KR</p>
        """,
        "apk_filename": "cj_delivery_track.apk",
        "permissions": [
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        ],
    },
    "wedding": {
        "title": "[모바일청첩장] 저희 두 사람의 소중한 시작",
        "body_html": """
            <h1>[모바일청첩장] 저희 두 사람의 소중한 시작을 함께 축복해 주세요</h1>
            <p>모바일 청첩장 보기 및 모바일 식권 다운로드를 위해 아래 앱(APK)을
               설치해 주세요.</p>
            <p>신랑 김민준 · 신부 이수아 드림</p>
        """,
        "apk_filename": "invitation.apk",
        "permissions": [
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.SEND_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        ],
    },
    "loan": {
        "title": "[정부지원] 2026 긴급 저금리 대출 승인 안내",
        "body_html": """
            <h1>[정부지원] 2026 긴급 소상공인 저금리 대출 승인 안내</h1>
            <p>귀하는 정부 긴급 지원금 대출 대상자로 사전 승인되었습니다. 대출금
               수령을 위해 본인인증 앱(APK)을 설치해 주세요.</p>
            <p>승인 한도: 30,000,000원 · 승인 유효기간: 오늘까지</p>
        """,
        "apk_filename": "gov_loan_grant.apk",
        "permissions": [
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.QUERY_ALL_PACKAGES",
            "android.permission.CALL_PHONE",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        ],
    },
    "police": {
        "title": "[경찰청] 긴급 압류 통지서 확인",
        "body_html": """
            <h1>[경찰청 사이버수사대] 긴급 압류 통지서 및 출석요구서</h1>
            <p>귀하의 명의로 개설된 계좌가 보이스피싱 및 불법 대출 사기에
               연루되어 긴급 압류 절차가 진행 중입니다.</p>
            <p>본인인증서 확인 후 세부 사건 내용을 열람하시려면 첨부된
               보안앱(APK)을 설치해 주세요.</p>
        """,
        "apk_filename": "invitation.apk",
        "permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.CALL_PHONE",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.QUERY_ALL_PACKAGES",
        ],
    },
}

DISCLAIMER_HTML = """
    <p style="color:#888;font-size:12px">
       ※ 본 페이지는 SafeShield 데모/테스트 목적의 무해한 고정 픽스처이며
       실제 기관·기업과 무관합니다. 실행 가능한 코드나 실제 악성코드를
       포함하지 않습니다.
    </p>
"""


def _landing_page_html(scenario_id: str, scenario: Dict[str, str]) -> str:
    return f"""
<!DOCTYPE html>
<html lang="ko">
<head><meta charset="utf-8"><title>{scenario['title']}</title></head>
<body>
  {scenario['body_html']}
  {DISCLAIMER_HTML}
  <script>
    // 실제 스미싱 사이트들이 흔히 쓰는 패턴(자동 리다이렉트 -> 자동 다운로드
    // 유도)을 SafeShield 샌드박스가 관찰할 수 있도록 재현한 데모용
    // 스크립트입니다. 방문자 기기에 아무 영향도 주지 않습니다.
    setTimeout(function () {{
      window.location.href = "/{scenario_id}/redirect-step";
    }}, 400);
  </script>
</body>
</html>
"""


def _download_page_html(scenario_id: str, scenario: Dict[str, str]) -> str:
    return f"""
<!DOCTYPE html>
<html lang="ko">
<head><meta charset="utf-8"><title>보안앱 다운로드 중...</title></head>
<body>
  <h1>앱을 다운로드하고 있습니다...</h1>
  <p>잠시만 기다려 주세요.</p>
  <script>
    setTimeout(function () {{
      window.location.href = "/{scenario_id}/{scenario['apk_filename']}";
    }}, 400);
  </script>
</body>
</html>
"""


def _manifest_xml(scenario: Dict[str, str]) -> str:
    perm_lines = "\n".join(
        f'    <uses-permission android:name="{p}" />' for p in scenario["permissions"]
    )
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="kr.test.safeshield.demo">
{perm_lines}
    <application android:label="SafeShield Demo Test Fixture (harmless, no executable code)">
    </application>
</manifest>
"""


README_TXT = (
    "This file is a SafeShield DEMO test fixture, not real malware.\n"
    "It is a plain ZIP archive containing only a text AndroidManifest.xml.\n"
    "It has NO classes.dex, NO native libraries, and NO executable code of\n"
    "any kind. It cannot be installed or run as a real Android app.\n"
    "It exists solely so SafeShield's static permission parser has a real\n"
    "file to analyze during demos.\n"
)


def _build_fixture_apk_bytes(scenario: Dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", _manifest_xml(scenario))
        zf.writestr("META-INF/README.txt", README_TXT)
    buf.seek(0)
    return buf.getvalue()


def _get_scenario_or_404(scenario_id: str) -> Dict[str, str]:
    scenario = SCENARIOS.get(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail=f"Unknown demo scenario: {scenario_id}")
    return scenario


# -----------------------------------------------------------------------
# IMPORTANT: literal-path routes (/, /healthz, /redirect-step, ...) MUST be
# registered BEFORE the /{scenario_id} catch-all below — FastAPI/Starlette
# matches routes in registration order, so a dynamic /{scenario_id} route
# registered first would otherwise swallow requests to e.g. /healthz
# (matching it as scenario_id="healthz" and 404'ing).
# -----------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def root_landing_page():
    # Backward-compatible root alias — behaves exactly like /police did
    # before the four scenarios were split out.
    return _landing_page_html("police", SCENARIOS["police"])


@app.get("/redirect-step")
async def root_redirect_step():
    return RedirectResponse(url="/download-page", status_code=302)


@app.get("/download-page", response_class=HTMLResponse)
async def root_download_page():
    return _download_page_html("police-root", {**SCENARIOS["police"], "apk_filename": "invitation.apk"})


@app.get("/invitation.apk")
async def root_fixture_apk():
    data = _build_fixture_apk_bytes(SCENARIOS["police"])
    headers = {"Content-Disposition": 'attachment; filename="invitation.apk"'}
    return Response(
        content=data,
        media_type="application/vnd.android.package-archive",
        headers=headers,
    )


@app.get("/healthz")
async def healthz():
    return {
        "status": "ok",
        "note": "This is a harmless SafeShield demo fixture server.",
        "scenarios": list(SCENARIOS.keys()),
    }


# -----------------------------------------------------------------------
# Per-scenario routes (must come AFTER the literal routes above)
# -----------------------------------------------------------------------

@app.get("/{scenario_id}", response_class=HTMLResponse)
async def scenario_landing_page(scenario_id: str):
    scenario = _get_scenario_or_404(scenario_id)
    return _landing_page_html(scenario_id, scenario)


@app.get("/{scenario_id}/redirect-step")
async def scenario_redirect_step(scenario_id: str):
    _get_scenario_or_404(scenario_id)
    # A genuine HTTP 302 redirect with a real Location header — SafeShield's
    # response listener will actually observe this, not a simulated one.
    return RedirectResponse(url=f"/{scenario_id}/download-page", status_code=302)


@app.get("/{scenario_id}/download-page", response_class=HTMLResponse)
async def scenario_download_page(scenario_id: str):
    scenario = _get_scenario_or_404(scenario_id)
    return _download_page_html(scenario_id, scenario)


@app.get("/{scenario_id}/{apk_filename}")
async def scenario_fixture_apk(scenario_id: str, apk_filename: str):
    scenario = _get_scenario_or_404(scenario_id)
    if apk_filename != scenario["apk_filename"]:
        raise HTTPException(status_code=404, detail="Unknown fixture file for this scenario")
    data = _build_fixture_apk_bytes(scenario)
    headers = {"Content-Disposition": f'attachment; filename="{apk_filename}"'}
    return Response(
        content=data,
        media_type="application/vnd.android.package-archive",
        headers=headers,
    )


if __name__ == "__main__":
    import uvicorn

    print("=" * 72)
    print("SafeShield DEMO Test Target Server — NOT a real phishing site.")
    print("Serving harmless, self-contained test fixtures at:")
    print("    http://127.0.0.1:9100/parcel   (CJ 택배 스미싱)")
    print("    http://127.0.0.1:9100/wedding  (모바일 청첩장 스미싱)")
    print("    http://127.0.0.1:9100/loan     (정부지원 대출 피싱)")
    print("    http://127.0.0.1:9100/police   (경찰 사칭, = 기존 루트 URL)")
    print("Point the SafeShield 'Malicious URL' (Custom URL) field at any of")
    print("these to demo the real detection -> lock pipeline end-to-end.")
    print("=" * 72)
    uvicorn.run(app, host="127.0.0.1", port=9100)