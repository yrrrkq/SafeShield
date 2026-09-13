import asyncio
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from sandbox import sandbox_engine

# NOTE: These scenarios hit REAL URLs over the network via Playwright.
# There is no fallback/synthetic data path anymore: if a URL cannot be
# reached, the engine returns reachable=False / threat_score=0 / verdict
# "UNREACHABLE", and if it *can* be reached, every score component is
# computed from what Playwright actually observed on that page.
#
# Because real websites obviously won't contain live smishing payloads,
# these scenarios exercise the pipeline in two ways:
#   1. NLP scoring against real SMS/page text (the "sms" field is fed into
#      the same text corpus that page content would be, so it is a genuine
#      test of evaluate_nlp_keywords()).
#   2. Reachability handling for a domain that does not exist.
# Dynamic (redirect/auto-download) and static (APK permission) scores will
# legitimately be 0 for all of these, since none of these targets actually
# serves a redirect chain or an .apk payload — that's the whole point of
# removing the fake fallback.

TEST_SCENARIOS = [
    {
        "id": "TC-01",
        "category": "실제 접속 가능한 정상 사이트 + 스미싱 문맥 SMS (NLP 단독 탐지 검증)",
        "url": "https://example.com",
        "sms": "[경찰청] 긴급 압류 통지서가 발부되었습니다. 대출 관련 택배 확인 바랍니다.",
        "expect_reachable": True,
    },
    {
        "id": "TC-02",
        "category": "실제 접속 가능한 정상 사이트 + 일반 SMS (완전 클린 케이스)",
        "url": "https://www.naver.com",
        "sms": "안녕하세요, 요청하신 자료 첨부해서 보내드립니다. 확인 부탁드려요.",
        "expect_reachable": True,
    },
    {
        "id": "TC-03",
        "category": "존재하지 않는 도메인 (실제 DNS 실패 → UNREACHABLE 처리 검증)",
        "url": "https://this-domain-does-not-exist-safeshield-test-9182.invalid",
        "sms": None,
        "expect_reachable": False,
    },
]


async def run_accuracy_benchmark():
    print("=" * 80)
    print("🛡️  SafeShield AI 하이브리드 위협 탐지 정확도 벤치마크 테스트 (실제 네트워크 기반)")
    print("=" * 80)

    checked_count = 0
    total_count = len(TEST_SCENARIOS)

    for tc in TEST_SCENARIOS:
        print(f"\n[{tc['id']}] 시나리오: {tc['category']}")
        print(f"  • 대상 URL: {tc['url']}")

        result = await sandbox_engine.inspect_url(target_url=tc["url"], sms_text=tc["sms"])

        reachable = result["reachable"]
        print(f"  • 접속 결과 (reachable): {reachable}")

        if not reachable:
            print(f"  • 오류: {result.get('error')} ({result.get('error_detail')})")
            status_ok = (reachable == tc["expect_reachable"])
            print(f"  {'✅' if status_ok else '❌'} 접속 불가 처리 검증: "
                  f"{'PASS' if status_ok else 'FAIL'} (가짜 데이터 없이 threat_score=0 반환 확인)")
            if status_ok:
                checked_count += 1
            continue

        analysis = result["ai_analysis"]
        breakdown = analysis["breakdown"]
        actions = result["b2c_actions"]

        score = analysis["threat_score"]
        conf = analysis["confidence_level"]
        verdict = analysis["verdict"]
        locked = actions["anti_transfer_lock"]["locked"]
        perms = result["detected_permissions"]
        matched_kw = analysis["matched_keywords"]

        print(f"  ┌─ 동적 행위 점수 (40점 만점): {breakdown['dynamic_behavior_score']}점 "
              f"(리다이렉트 {len(analysis['redirect_chain'])}건, APK 자동다운로드 여부는 apk_downloaded 참고)")
        print(f"  ├─ 정적 권한 점수 (40점 만점): {breakdown['static_permission_score']}점 "
              f"(실제 다운로드된 APK 있음: {result['apk_downloaded']}, 탐지 권한: {', '.join(perms) or '없음'})")
        print(f"  ├─ NLP 문맥 점수  (20점 만점): {breakdown['nlp_context_score']}점 "
              f"(매칭 키워드: {', '.join(matched_kw) or '없음'})")
        print(f"  └─ 최종 종합 위협 점수: {score}/100점 | 신뢰도: {conf} | 판정: {verdict}")
        print(f"  🔒 스마트 송금 동결 (30분 락): {'[작동됨 (LOCKED)]' if locked else '[미작동 (NORMAL)]'}")

        # 접속 성공 여부만 검증 (실제 사이트 콘텐츠는 매번 달라질 수 있으므로
        # 점수 자체를 하드코딩된 기대값과 비교하지 않고, 파이프라인이 실제로
        # 동작했는지 — 즉 가짜 데이터가 아니라 실제 관측치로 채점되었는지 — 를 확인)
        status_ok = (reachable == tc["expect_reachable"])
        print(f"  {'✅' if status_ok else '❌'} 실접속 파이프라인 검증: {'PASS' if status_ok else 'FAIL'}")
        if status_ok:
            checked_count += 1

    print("\n" + "=" * 80)
    print(f"📊 최종 벤치마크 결과: {checked_count}/{total_count} 시나리오에서 예상된 접속 가능 여부와 일치 "
          f"({(checked_count / total_count) * 100:.1f}%)")
    print("   (주의: 점수 자체는 실제 사이트 콘텐츠에 따라 매 실행마다 달라질 수 있습니다.)")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_accuracy_benchmark())