#!/usr/bin/env python3
"""
Tuần 1 — Seed báo cáo Semgrep/ZAP demo vào data-lake rồi parse → SQLite.

Mặc định tạo corpus ~140 findings (111 SAST + 29 DAST) khớp quy mô docs tuần 3,
có trùng lặp có chủ đích để demo gộp nhóm. Không cần chạy scan thật.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "data-lake" / "reports"
DB = ROOT / "data-lake" / "vuln_data.db"
CI_ZAP = ROOT / "data-lake" / "ci-artifacts" / "zap-scan-report" / "report_json.json"

# Đường dẫn thật trong Juice Shop (pin v20) — không bịa endpoint/file ngoài repo.
PATHS = [
    "juice-shop/routes/search.ts",
    "juice-shop/routes/login.ts",
    "juice-shop/routes/basket.ts",
    "juice-shop/routes/fileServer.ts",
    "juice-shop/routes/redirect.ts",
    "juice-shop/routes/userProfile.ts",
    "juice-shop/routes/updateUserProfile.ts",
    "juice-shop/routes/trackOrder.ts",
    "juice-shop/routes/changePassword.ts",
    "juice-shop/routes/chat.ts",
    "juice-shop/routes/order.ts",
    "juice-shop/routes/b2bOrder.ts",
    "juice-shop/routes/memory.ts",
    "juice-shop/routes/metrics.ts",
    "juice-shop/routes/deluxe.ts",
    "juice-shop/routes/coupon.ts",
    "juice-shop/routes/dataExport.ts",
    "juice-shop/routes/fileUpload.ts",
    "juice-shop/routes/currentUser.ts",
    "juice-shop/routes/showProductReviews.ts",
    "juice-shop/routes/createProductReviews.ts",
    "juice-shop/routes/recycles.ts",
    "juice-shop/routes/securityQuestion.ts",
    "juice-shop/server.ts",
    "juice-shop/lib/insecurity.ts",
    "juice-shop/models/user.ts",
    "juice-shop/models/basket.ts",
    "juice-shop/models/product.ts",
    "juice-shop/routes/profileImageFileUpload.ts",
    "juice-shop/routes/quarantineServer.ts",
    "juice-shop/routes/logfileServer.ts",
    "juice-shop/routes/keyServer.ts",
    "juice-shop/routes/nftMint.ts",
    "juice-shop/routes/2fa.ts",
    "juice-shop/routes/captcha.ts",
    "juice-shop/routes/imageCaptcha.ts",
    "juice-shop/routes/authenticatedUsers.ts",
]

# (check_id, severity, message) — rule id kiểu Semgrep
RULES = [
    ("javascript.lang.security.audit.sqli.node-sqli", "ERROR", "SQL Injection: user input concatenated into query."),
    ("javascript.lang.security.audit.sqli.node-sqli", "ERROR", "SQL Injection sink via Sequelize string concat."),
    ("javascript.express.security.audit.xss.direct-response-write", "WARNING", "Potential XSS via unsanitized reflection."),
    ("javascript.express.security.audit.xss.direct-response-write", "WARNING", "Reflected XSS: response writes user input."),
    ("javascript.express.security.audit.express-check-csurf", "INFO", "Missing CSRF protection on state-changing routes."),
    ("javascript.lang.security.audit.path-traversal.path-join-resolve-traversal", "ERROR", "Path traversal via user-controlled path join."),
    ("javascript.lang.security.audit.path-traversal.path-join-resolve-traversal", "ERROR", "Unsanitized path segment reaches filesystem API."),
    ("javascript.express.security.audit.express-open-redirect", "WARNING", "Open redirect from unvalidated redirect URL."),
    ("javascript.lang.security.audit.detect-eval-with-expression", "ERROR", "Use of eval/Function with dynamic input."),
    ("javascript.lang.security.audit.detect-child-process", "WARNING", "child_process invoked with potentially tainted input."),
    ("javascript.express.security.audit.express-jwt-hardcoded-secret", "ERROR", "Hardcoded JWT secret detected."),
    ("javascript.lang.security.audit.hardcoded-secret", "WARNING", "Possible hardcoded credential or API token."),
    ("javascript.express.security.audit.cookie-session-no-secure", "INFO", "Session cookie missing Secure/HttpOnly flags."),
    ("javascript.lang.security.audit.prototype-pollution", "WARNING", "Prototype pollution via recursive merge."),
    ("javascript.express.security.audit.express-check-content-type", "INFO", "Missing content-type validation on upload."),
    ("javascript.lang.security.audit.xss.mustache", "WARNING", "Template may render unsanitized HTML."),
    ("javascript.lang.security.audit.ssrf", "ERROR", "Server-side request forgery: URL from request."),
    ("javascript.lang.security.audit.deserialize", "ERROR", "Unsafe deserialization of user-controlled data."),
]

# ZAP alerts bổ sung (Juice Shop localhost) — cộng với CI artifact nếu có
EXTRA_ZAP_ALERTS = [
    {
        "name": "SQL Injection",
        "riskdesc": "High (High)",
        "desc": "The q parameter in /rest/products/search appears vulnerable to SQLi.",
        "instances": [
            {"uri": "http://localhost:3000/rest/products/search?q='"},
            {"uri": "http://localhost:3000/rest/products/search?q=%27%20OR%201%3D1--"},
            {"uri": "http://localhost:3000/rest/products/search?q=apple'+OR+'1'='1"},
        ],
    },
    {
        "name": "Cross Site Scripting (Reflected)",
        "riskdesc": "Medium (Medium)",
        "desc": "Search reflects unsanitized input.",
        "instances": [
            {"uri": "http://localhost:3000/rest/products/search?q=<script>alert(1)</script>"},
            {"uri": "http://localhost:3000/rest/products/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E"},
        ],
    },
    {
        "name": "Absence of Anti-CSRF Tokens",
        "riskdesc": "Low (Medium)",
        "desc": "Forms may lack CSRF tokens.",
        "instances": [
            {"uri": "http://localhost:3000/#/login"},
            {"uri": "http://localhost:3000/#/register"},
        ],
    },
    {
        "name": "Path Traversal",
        "riskdesc": "High (Medium)",
        "desc": "File endpoints may allow directory traversal.",
        "instances": [
            {"uri": "http://localhost:3000/ftp/../../etc/passwd"},
            {"uri": "http://localhost:3000/assets/public/images/../../package.json"},
        ],
    },
    {
        "name": "Application Error Disclosure",
        "riskdesc": "Medium (Medium)",
        "desc": "Error responses disclose stack traces or internal paths.",
        "instances": [{"uri": "http://localhost:3000/rest/user/login"}],
    },
    {
        "name": "Incomplete or No Cache-control Header Set",
        "riskdesc": "Low (Medium)",
        "desc": "Sensitive responses lack Cache-Control.",
        "instances": [
            {"uri": "http://localhost:3000/rest/user/whoami"},
            {"uri": "http://localhost:3000/api/Users"},
        ],
    },
    {
        "name": "X-Content-Type-Options Header Missing",
        "riskdesc": "Low (Medium)",
        "desc": "Missing X-Content-Type-Options: nosniff.",
        "instances": [{"uri": "http://localhost:3000/"}, {"uri": "http://localhost:3000/rest/products/search"}],
    },
]


def build_semgrep(target: int = 111) -> dict:
    """Sinh ~target kết quả Semgrep; tập trung trùng (cùng rule+path) để demo gộp ~2–3×."""
    results = []
    # Chỉ dùng subset path để tăng mật độ trùng → ~50 findings sau group
    hot_paths = PATHS[:14]
    i = 0
    while len(results) < target:
        rule = RULES[i % len(RULES)]
        path = hot_paths[i % len(hot_paths)]
        check_id, severity, message = rule
        # Mỗi (rule, path) sinh 2–3 hit → group_findings gộp
        for hit in range(2 + (i % 2)):
            if len(results) >= target:
                break
            results.append(
                {
                    "check_id": check_id,
                    "path": path,
                    "extra": {
                        "severity": severity,
                        "message": f"{message} (hit #{len(results) + 1}, variant {hit})",
                    },
                }
            )
        i += 1
    return {"results": results[:target], "errors": []}


def _zap_from_ci() -> list[dict]:
    if not CI_ZAP.exists():
        return []
    try:
        data = json.loads(CI_ZAP.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    alerts: list[dict] = []
    for site in data.get("site") or []:
        for alert in site.get("alerts") or []:
            alerts.append(
                {
                    "name": alert.get("name") or alert.get("alert") or "Unknown",
                    "riskdesc": alert.get("riskdesc") or alert.get("riskcode") or "UNKNOWN",
                    "desc": alert.get("desc") or "",
                    "instances": alert.get("instances") or [{"uri": "http://localhost:3000/"}],
                }
            )
    return alerts


def build_zap(target: int = 29) -> dict:
    """Gộp CI ZAP + EXTRA; expand mỗi instance thành alert riêng → ~target rows khi parse 1-url/alert."""
    merged: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for src in _zap_from_ci() + EXTRA_ZAP_ALERTS:
        for inst in src.get("instances") or [{"uri": "http://localhost:3000/"}]:
            uri = (inst or {}).get("uri") or "http://localhost:3000/"
            key = (src["name"], uri.split("?")[0])
            if key in seen:
                # vẫn thêm với query khác nếu còn thiếu quota
                key = (src["name"], uri)
            if key in seen and len(merged) >= target:
                continue
            seen.add(key)
            merged.append(
                {
                    "name": src["name"],
                    "riskdesc": src["riskdesc"],
                    "riskcode": "3" if "High" in src["riskdesc"] else "2",
                    "desc": src["desc"],
                    "instances": [{"uri": uri}],
                }
            )
            if len(merged) >= target:
                break
        if len(merged) >= target:
            break

    # Pad nếu thiếu: lặp SQLi search với query khác
    n = 0
    while len(merged) < target:
        n += 1
        merged.append(
            {
                "name": "SQL Injection",
                "riskdesc": "High (High)",
                "desc": "Repeated SQLi probe on product search (seed pad).",
                "instances": [{"uri": f"http://localhost:3000/rest/products/search?q=pad{n}"}],
            }
        )

    return {"site": [{"@name": "http://localhost:3000", "alerts": merged[:target]}]}


def write_reports(*, semgrep_n: int, zap_n: int) -> tuple[Path, Path]:
    REPORTS.mkdir(parents=True, exist_ok=True)
    semgrep_path = REPORTS / "semgrep-sample.json"
    zap_path = REPORTS / "zap-sample.json"
    semgrep_path.write_text(json.dumps(build_semgrep(semgrep_n), indent=2), encoding="utf-8")
    zap_path.write_text(json.dumps(build_zap(zap_n), indent=2), encoding="utf-8")
    print(f"[+] Wrote {semgrep_path} ({semgrep_n} results)")
    print(f"[+] Wrote {zap_path} ({zap_n} alerts)")
    return semgrep_path, zap_path


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed Semgrep/ZAP demo reports → vuln_data.db")
    ap.add_argument("--semgrep-n", type=int, default=111, help="Số kết quả Semgrep (mặc định 111)")
    ap.add_argument("--zap-n", type=int, default=29, help="Số alert ZAP (mặc định 29)")
    ap.add_argument("--mini", action="store_true", help="Corpus nhỏ 3+3 (debug nhanh)")
    args = ap.parse_args()

    if args.mini:
        semgrep_n, zap_n = 3, 3
    else:
        semgrep_n, zap_n = args.semgrep_n, args.zap_n

    semgrep_path, zap_path = write_reports(semgrep_n=semgrep_n, zap_n=zap_n)

    parse_script = ROOT / "scripts" / "parse_results.py"
    cmd = [
        sys.executable,
        str(parse_script),
        "--semgrep",
        str(semgrep_path),
        "--zap",
        str(zap_path),
        "--db",
        str(DB),
        "--replace",
    ]
    print(f"[*] Running: {' '.join(cmd)}")
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(cmd, cwd=ROOT, env=env)
    if result.returncode == 0:
        print(f"[+] DB ready → {DB}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
