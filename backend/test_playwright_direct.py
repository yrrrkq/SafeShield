"""
SafeShield DEBUG: Direct Playwright -> localhost connectivity test.

Run this on its own (test_target_server.py must already be running on
port 9100) to check, completely independent of main.py/sandbox.py,
whether Playwright's Chromium can reach the local fixture server at all.

    python test_playwright_direct.py

If this script also fails, the problem is NOT in SafeShield's code — it's
something environmental (proxy, firewall, antivirus) blocking Chromium
from reaching 127.0.0.1 on this machine. If this script SUCCEEDS but the
SafeShield backend still reports "unreachable", the problem is something
specific to how main.py/sandbox.py launches the browser (and the full
error text this script prints from sandbox.py's own log line will be the
key clue — see the WARNING line in the uvicorn console).
"""

import sys
from playwright.sync_api import sync_playwright

TARGET = "http://127.0.0.1:9100/healthz"

print("=" * 70)
print(f"Attempting to reach: {TARGET}")
print("A visible Chromium window should open (headless=False) so you can")
print("SEE whether it actually loads the page or shows an error screen.")
print("=" * 70)

try:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()
        response = page.goto(TARGET, wait_until="domcontentloaded", timeout=15000)
        print(f"\n✅ SUCCESS — HTTP status: {response.status}")
        print("Page body:", page.inner_text("body")[:300])
        input("\n(브라우저 창을 확인한 뒤, 여기서 Enter를 누르면 종료됩니다) ")
        browser.close()
except Exception as e:
    print("\n❌ FAILED — full error below:\n")
    print(repr(e))
    print("\n이 에러 메시지 전체를 그대로 복사해서 보여주세요.")
    sys.exit(1)