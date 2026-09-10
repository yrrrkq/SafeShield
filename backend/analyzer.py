import asyncio
import hashlib
import io
import logging
import os
import re
import time
import uuid
import zipfile
from typing import AsyncGenerator, Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("safeshield.analyzer")
logging.basicConfig(level=logging.INFO)

# Sandbox isolation directory (shared with sandbox.py's engine)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TMP_SANDBOX_DIR = os.path.join(BASE_DIR, "tmp_sandbox")
os.makedirs(TMP_SANDBOX_DIR, exist_ok=True)

# Predefined dangerous Android permissions & risk weights (Static Analysis, Max 40 pts)
PERMISSION_RISK_MAP = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "weight": 30,
        "name": "Accessibility Service Hijack",
        "danger": "CRITICAL",
        "description": "Can read screen content, tap buttons automatically, and steal banking credentials/PINs without user consent."
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "weight": 25,
        "name": "Overlay Injection (Fake Banking UI)",
        "danger": "CRITICAL",
        "description": "Allows malicious overlay windows over legitimate banking & crypto apps to intercept passwords."
    },
    "android.permission.READ_SMS": {
        "weight": 20,
        "name": "SMS Read & OTP Interception",
        "danger": "HIGH",
        "description": "Reads incoming SMS messages to steal 2FA authentication codes and financial OTPs."
    },
    "android.permission.RECEIVE_SMS": {
        "weight": 20,
        "name": "Silent SMS Interception",
        "danger": "HIGH",
        "description": "Intercepts incoming bank notification SMS and deletes them before victim sees."
    },
    "android.permission.SEND_SMS": {
        "weight": 15,
        "name": "Outbound Smishing Bot",
        "danger": "HIGH",
        "description": "Sends unauthorized mass smishing texts to all contacts in background."
    },
    "android.permission.CALL_PHONE": {
        "weight": 18,
        "name": "Call Hijacking & Redirect",
        "danger": "HIGH",
        "description": "Intercepts outbound calls to Financial Supervisory Service or 112 and redirects to scam call centers."
    },
    "android.permission.RECORD_AUDIO": {
        "weight": 15,
        "name": "Microphone Eavesdropping",
        "danger": "HIGH",
        "description": "Listens to private phone conversations and ambient audio in real time."
    },
    "android.permission.READ_CONTACTS": {
        "weight": 10,
        "name": "Contact Book Harvesting",
        "danger": "MEDIUM",
        "description": "Uploads family & friend contact lists to C2 server for secondary extortion."
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "weight": 10,
        "name": "Installed Banking App Enumeration",
        "danger": "MEDIUM",
        "description": "Scans installed banking, crypto, and security apps to deploy targeted overlays."
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "weight": 8,
        "name": "Auto-Start on Device Boot",
        "danger": "LOW",
        "description": "Ensures Trojan restarts automatically whenever the smartphone is rebooted."
    }
}

# Known Smishing & Phishing Heuristic Keywords (used both for SMS intent triage
# and for real NLP scoring against actual page/SMS text)
PHISHING_KEYWORDS = [
    "cj", "delivery", "track", "package", "wedding", "invitation", "loan", "police",
    "kisa", "fss", "support", "secure", "apk", "bank", "check", "refund", "tax",
    "택배", "배송", "청첩장", "대출", "경찰", "검찰", "금감원", "보안앱", "조회", "환급"
]

# DOM cues that suggest a page is impersonating an institution / requesting sensitive info
INSTITUTION_IMPERSONATION_CUES = [
    "경찰청", "검찰청", "금융감독원", "보안인증", "공공기관",
    "인증서", "계좌", "주민등록번호", "휴대폰 본인확인", "보안앱 설치"
]


def _now() -> str:
    return time.strftime("%H:%M:%S")


class SandboxAnalyzer:
    def __init__(self):
        self.playwright_available = False
        try:
            from playwright.async_api import async_playwright  # noqa: F401
            self.playwright_available = True
        except ImportError:
            self.playwright_available = False

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------
    def generate_sha256(self, payload: bytes) -> str:
        """Computes the true SHA-256 hash of a real payload binary."""
        return hashlib.sha256(payload).hexdigest()

    def analyze_sms_intent(self, text: str) -> Dict[str, Any]:
        """
        Deterministic keyword-based intent classification of the incoming
        SMS/URL text. This only labels the *category* of scam being imitated —
        it does not by itself produce a score; the actual threat score is
        computed later from real browser/DOM/APK observations.
        """
        lower = text.lower()
        matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in lower]

        threat_type = "Generic Suspicious Link"
        category = "Smishing"

        if any(k in lower for k in ["택배", "배송", "cj", "delivery", "track", "우체국"]):
            threat_type = "CJ/Post Parcel Delivery Smishing (Trojan.Dropper)"
            category = "Smishing"
        elif any(k in lower for k in ["청첩장", "wedding", "invitation", "모바일 청첩장"]):
            threat_type = "Mobile Wedding Invitation Smishing (Trojan.Spy)"
            category = "Smishing"
        elif any(k in lower for k in ["대출", "loan", "금리", "지원금", "정부지원"]):
            threat_type = "Emergency Loan / Gov Grant Phishing (Trojan.Banker)"
            category = "Voice Phishing / Loan Scam"
        elif any(k in lower for k in ["경찰", "검찰", "수사", "police", "fss", "보안앱"]):
            threat_type = "Fake Police / Prosecutor Wiretap App (Trojan.Spy.CallHijack)"
            category = "Voice Phishing Wiretap"

        url_match = re.search(r'(https?://[^\s]+)', text)
        extracted_url = url_match.group(0) if url_match else None

        return {
            "threat_type": threat_type,
            "category": category,
            "matched_keywords": matched_keywords,
            "extracted_url": extracted_url
        }

    def evaluate_nlp_score(self, text: str) -> Tuple[int, List[str]]:
        """
        Scans REAL text (page DOM + SMS content) for phishing keywords.
        Returns (nlp_score, matched_keywords). Max score: 20 pts.
        No hardcoded overrides — purely a function of the observed text.
        """
        lower_text = text.lower()
        matches = [kw for kw in PHISHING_KEYWORDS if kw in text or kw.lower() in lower_text]

        if len(matches) >= 3:
            score = 20
        elif len(matches) == 2:
            score = 15
        elif len(matches) == 1:
            score = 10
        else:
            score = 0

        return min(20, score), matches

    def _parse_manifest_permissions(self, apk_bytes: bytes) -> List[str]:
        """
        Statically inspects a REAL downloaded APK's AndroidManifest.xml for
        dangerous permission strings. Returns [] if not a valid archive or if
        none of the monitored permissions are present.
        """
        found: List[str] = []
        try:
            with zipfile.ZipFile(io.BytesIO(apk_bytes)) as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_bytes = zf.read("AndroidManifest.xml")
                    text = manifest_bytes.decode("utf-8", errors="ignore")
                    for perm in PERMISSION_RISK_MAP:
                        if perm in text:
                            found.append(perm)
        except zipfile.BadZipFile:
            logger.info("Downloaded file is not a valid ZIP/APK archive — static score = 0.")
        except Exception as e:
            logger.debug(f"Manifest parse error: {e}")
        return found

    def _extract_package_name(self, apk_bytes: bytes) -> Optional[str]:
        """Attempts to read the real 'package' attribute out of the manifest."""
        try:
            with zipfile.ZipFile(io.BytesIO(apk_bytes)) as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_bytes = zf.read("AndroidManifest.xml")
                    text = manifest_bytes.decode("utf-8", errors="ignore")
                    m = re.search(r'package="([^"]+)"', text)
                    if m:
                        return m.group(1)
        except Exception:
            pass
        return None

    def _domain_based_package_name(self, url: str) -> str:
        """Fallback package-name-style label derived from the real target domain."""
        try:
            netloc = urlparse(url).netloc or url
            netloc = netloc.split(":")[0]
            parts = [p for p in netloc.split(".") if p]
            if len(parts) >= 2:
                return ".".join(reversed(parts))
            return netloc or "unknown.target"
        except Exception:
            return "unknown.target"

    # -----------------------------------------------------------------
    # Main streaming analysis
    # -----------------------------------------------------------------
    async def run_sandbox_stream(
        self,
        url: str,
        sms_text: Optional[str] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Executes REAL step-by-step sandbox analysis and yields real-time
        terminal events. No fabricated data, no artificial "for-show" sleeps —
        the only sleeps present are small (0.1s) pacing delays so a WebSocket
        client can render events as a stream rather than receiving one giant
        burst.
        """
        # -------------------------------------------------------------
        # Step 1: SMS Context & URL parsing (deterministic keyword triage)
        # -------------------------------------------------------------
        yield {
            "step": 1,
            "stage": "SMS_INTENT_TRIAGE",
            "level": "INFO",
            "message": f"[*] Initiating SafeShield Sandbox for target URL: {url}",
            "timestamp": _now()
        }
        await asyncio.sleep(0.1)

        sms_analysis = self.analyze_sms_intent(sms_text or url)
        yield {
            "step": 1,
            "stage": "SMS_INTENT_TRIAGE",
            "level": "ANALYSIS",
            "message": (
                f"[+] Intent category: {sms_analysis['threat_type']} "
                f"(Keywords: {', '.join(sms_analysis['matched_keywords']) or 'none'})"
            ),
            "timestamp": _now()
        }
        await asyncio.sleep(0.1)

        # -------------------------------------------------------------
        # Step 2: REAL Headless Browser Sandbox Execution
        # -------------------------------------------------------------
        yield {
            "step": 2,
            "stage": "HEADLESS_BROWSER_SANDBOX",
            "level": "SANDBOX",
            "message": "[*] Launching real Chromium sandbox instance via Playwright...",
            "timestamp": _now()
        }
        await asyncio.sleep(0.1)

        redirect_chain: List[str] = []
        auto_download_triggered = False
        apk_content_type_detected = False
        institution_cues_detected = False
        downloaded_bytes: Optional[bytes] = None
        temp_apk_path: Optional[str] = None
        page_text_corpus = f"{sms_text or ''}"
        connection_error: Optional[str] = None
        playwright_succeeded = False

        try:
            from playwright.async_api import async_playwright
        except ImportError as e:
            connection_error = f"Playwright not installed: {e}"
            yield {
                "step": 2,
                "stage": "HEADLESS_BROWSER_SANDBOX",
                "level": "ERROR",
                "message": f"[!] {connection_error}",
                "timestamp": _now()
            }
        else:
            try:
                async with async_playwright() as p:
                    browser = await p.chromium.launch(
                        headless=True,
                        args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
                    )
                    context = await browser.new_context(
                        user_agent=(
                            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
                        ),
                        viewport={"width": 412, "height": 915},
                        accept_downloads=True
                    )
                    page = await context.new_page()

                    async def on_response(response):
                        nonlocal apk_content_type_detected
                        if 300 <= response.status < 400:
                            loc = response.headers.get("location")
                            if loc:
                                redirect_chain.append(loc)
                        ctype = response.headers.get("content-type", "")
                        if "application/vnd.android.package-archive" in ctype:
                            apk_content_type_detected = True
                    page.on("response", on_response)

                    download_future = asyncio.get_event_loop().create_future()

                    async def on_download(download):
                        nonlocal auto_download_triggered
                        auto_download_triggered = True
                        if not download_future.done():
                            download_future.set_result(download)
                    page.on("download", on_download)

                    try:
                        yield {
                            "step": 2,
                            "stage": "HEADLESS_BROWSER_SANDBOX",
                            "level": "SANDBOX",
                            "message": f"[*] Navigating to {url} ...",
                            "timestamp": _now()
                        }

                        response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                        if response is None:
                            raise RuntimeError("No HTTP response received from target (empty response).")

                        if page.url != url and page.url not in redirect_chain:
                            redirect_chain.append(page.url)

                        yield {
                            "step": 2,
                            "stage": "HEADLESS_BROWSER_SANDBOX",
                            "level": "SANDBOX",
                            "message": f"[+] Real page load complete: {page.url} (redirects observed: {len(redirect_chain)})",
                            "timestamp": _now()
                        }
                        await asyncio.sleep(0.1)

                        body_text = await page.inner_text("body")
                        page_text_corpus += f" {body_text}"

                        institution_cues_detected = any(c in page_text_corpus for c in INSTITUTION_IMPERSONATION_CUES)
                        if institution_cues_detected:
                            yield {
                                "step": 2,
                                "stage": "HEADLESS_BROWSER_SANDBOX",
                                "level": "ALERT",
                                "message": "[!] Real DOM text contains institution-impersonation cues.",
                                "timestamp": _now()
                            }
                        await asyncio.sleep(0.1)

                        # Wait briefly for a real automatic download event
                        try:
                            dl = await asyncio.wait_for(download_future, timeout=3.0)
                            suggested_name = dl.suggested_filename
                            temp_apk_path = os.path.join(
                                TMP_SANDBOX_DIR, f"apk_{uuid.uuid4().hex[:8]}_{suggested_name}"
                            )
                            await dl.save_as(temp_apk_path)
                            with open(temp_apk_path, "rb") as f:
                                downloaded_bytes = f.read()
                        except asyncio.TimeoutError:
                            pass

                        playwright_succeeded = True

                    except Exception as nav_err:
                        connection_error = str(nav_err)
                        yield {
                            "step": 2,
                            "stage": "HEADLESS_BROWSER_SANDBOX",
                            "level": "ERROR",
                            "message": f"[!] Navigation failed for {url}: {nav_err}",
                            "timestamp": _now()
                        }
                    finally:
                        await context.close()
                        await browser.close()

            except Exception as pw_err:
                connection_error = str(pw_err)
                yield {
                    "step": 2,
                    "stage": "HEADLESS_BROWSER_SANDBOX",
                    "level": "ERROR",
                    "message": f"[!] Playwright engine failure: {pw_err}",
                    "timestamp": _now()
                }

        # -------------------------------------------------------------
        # If the browser never actually reached the target, stop here with
        # an explicit zero-score / unreachable result. No fabricated data.
        # -------------------------------------------------------------
        if not playwright_succeeded:
            yield {
                "step": 5,
                "stage": "RISK_EVALUATION",
                "level": "ALERT",
                "message": f"[!] Target unreachable — analysis aborted, threat score = 0. Reason: {connection_error}",
                "timestamp": _now(),
                "data": {
                    "riskScore": 0,
                    "verdict": "UNREACHABLE",
                    "threatType": sms_analysis["threat_type"],
                    "packageName": None,
                    "permissions": [],
                    "sha256": None,
                    "url": url,
                    "error": connection_error
                }
            }
            return

        # -------------------------------------------------------------
        # Step 3: REAL APK Payload Interception & SHA-256 Hashing
        # -------------------------------------------------------------
        yield {
            "step": 3,
            "stage": "APK_INTERCEPT",
            "level": "DECOMPILER",
            "message": "[*] Checking for an intercepted APK payload from the real browser session...",
            "timestamp": _now()
        }
        await asyncio.sleep(0.1)

        apk_hash: Optional[str] = None
        detected_permissions: List[str] = []
        package_name: Optional[str] = None

        try:
            if downloaded_bytes:
                sha256_hash = self.generate_sha256(downloaded_bytes)
                apk_hash = f"0x{sha256_hash}"
                yield {
                    "step": 3,
                    "stage": "APK_INTERCEPT",
                    "level": "CRYPTO",
                    "message": f"[+] Real APK payload intercepted. SHA-256 fingerprint: {apk_hash}",
                    "timestamp": _now(),
                    "data": {"sha256": apk_hash}
                }
                await asyncio.sleep(0.1)

                # -----------------------------------------------------
                # Step 4: REAL Static Permission Parsing (ZipFile / AndroidManifest)
                # -----------------------------------------------------
                yield {
                    "step": 4,
                    "stage": "STATIC_PERMISSION_AUDIT",
                    "level": "DECOMPILER",
                    "message": "[*] Parsing real AndroidManifest.xml from the downloaded APK...",
                    "timestamp": _now()
                }
                await asyncio.sleep(0.1)

                detected_permissions = self._parse_manifest_permissions(downloaded_bytes)
                package_name = self._extract_package_name(downloaded_bytes) or self._domain_based_package_name(url)

                if not detected_permissions:
                    yield {
                        "step": 4,
                        "stage": "STATIC_PERMISSION_AUDIT",
                        "level": "INFO",
                        "message": "[-] No monitored dangerous permissions found in manifest.",
                        "timestamp": _now()
                    }
                for perm in detected_permissions:
                    meta = PERMISSION_RISK_MAP.get(perm, {"name": perm, "danger": "MEDIUM", "description": "System access"})
                    yield {
                        "step": 4,
                        "stage": "STATIC_PERMISSION_AUDIT",
                        "level": "WARNING" if meta["danger"] in ["HIGH", "CRITICAL"] else "INFO",
                        "message": f"    ├── [DANGEROUS_PERM] {perm} -> {meta['name']} ({meta['danger']})",
                        "timestamp": _now()
                    }
                    await asyncio.sleep(0.1)
            else:
                yield {
                    "step": 3,
                    "stage": "APK_INTERCEPT",
                    "level": "INFO",
                    "message": "[-] No APK was downloaded during this session — static permission score will be 0.",
                    "timestamp": _now()
                }
                await asyncio.sleep(0.1)
                yield {
                    "step": 4,
                    "stage": "STATIC_PERMISSION_AUDIT",
                    "level": "INFO",
                    "message": "[-] Skipping manifest parsing: no APK file present.",
                    "timestamp": _now()
                }
                package_name = self._domain_based_package_name(url) if apk_content_type_detected else None

        finally:
            # Strict isolation: purge any downloaded file from disk, regardless of outcome
            if temp_apk_path and os.path.exists(temp_apk_path):
                try:
                    os.remove(temp_apk_path)
                    logger.info(f"Isolated sandbox file purged: {temp_apk_path}")
                except OSError as err:
                    logger.error(f"Failed to remove sandbox file {temp_apk_path}: {err}")

        # -------------------------------------------------------------
        # Step 5: Hybrid Threat Scoring (purely from real observed signals)
        # -------------------------------------------------------------

        # a) Dynamic Behavior Score (Max: 40 pts) — real signals only
        dynamic_score = 0
        if auto_download_triggered or apk_content_type_detected:
            dynamic_score += 20
        if len(redirect_chain) > 0:
            dynamic_score += 10
        if institution_cues_detected:
            dynamic_score += 10
        dynamic_score = min(40, dynamic_score)

        # b) Static Permission Score (Max: 40 pts) — 0 unless a real APK was parsed
        static_score = 0
        permission_details = []
        for perm in detected_permissions:
            meta = PERMISSION_RISK_MAP.get(perm, {"weight": 5, "name": perm, "danger": "MEDIUM", "description": "System access"})
            static_score += meta["weight"]
            permission_details.append({
                "permission": perm,
                "name": meta["name"],
                "danger": meta["danger"],
                "description": meta["description"]
            })
        static_score = min(40, static_score)

        # c) NLP Context Score (Max: 20 pts) — computed only from real page/SMS text
        nlp_score, matched_kw = self.evaluate_nlp_score(page_text_corpus)

        total_risk_score = min(100, dynamic_score + static_score + nlp_score)
        verdict = (
            "CRITICAL_MALWARE" if total_risk_score >= 80 else
            "HIGH_RISK" if total_risk_score >= 50 else
            "SUSPICIOUS" if total_risk_score >= 20 else
            "CLEAN"
        )

        yield {
            "step": 5,
            "stage": "RISK_EVALUATION",
            "level": "CRITICAL" if total_risk_score >= 80 else "ALERT",
            "message": (
                f"[🚨] AI Threat Score: {total_risk_score}/100 | Verdict: {verdict} | "
                f"Category: {sms_analysis['threat_type']}"
            ),
            "timestamp": _now(),
            "data": {
                "riskScore": total_risk_score,
                "verdict": verdict,
                "threatType": sms_analysis["threat_type"],
                "packageName": package_name,
                "permissions": permission_details,
                "sha256": apk_hash,
                "url": url,
                "breakdown": {
                    "dynamic_behavior_score": dynamic_score,
                    "static_permission_score": static_score,
                    "nlp_context_score": nlp_score
                },
                "matchedKeywords": matched_kw,
                "redirectChain": redirect_chain
            }
        }
        await asyncio.sleep(0.1)

        # -------------------------------------------------------------
        # Step 6: Blockchain Multi-Sig Trigger Preparation
        # (main.py / the websocket handler decide whether to actually
        # propose based on riskScore/apk_hash — this step is informational.)
        # -------------------------------------------------------------
        if apk_hash and total_risk_score >= 70:
            yield {
                "step": 6,
                "stage": "ORACLE_PREPARE",
                "level": "BLOCKCHAIN",
                "message": "[*] Preparing SafeShield On-Chain Multi-Sig Proposal (Target Threshold: 2 of 4 Nodes)...",
                "timestamp": _now()
            }
        else:
            yield {
                "step": 6,
                "stage": "ORACLE_PREPARE",
                "level": "INFO",
                "message": "[-] Threat score below on-chain proposal threshold or no verified APK hash — skipping oracle registration.",
                "timestamp": _now()
            }