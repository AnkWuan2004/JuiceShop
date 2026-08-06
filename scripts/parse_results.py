#!/usr/bin/env python3
"""Parse SAST/DAST results into Data Lake (SQLite)."""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def init_db(db_path: str):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool TEXT,
        severity TEXT,
        name TEXT,
        description TEXT,
        path_or_url TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """
    )
    conn.commit()
    return conn


def clear_vulnerabilities(conn) -> None:
    conn.execute("DELETE FROM vulnerabilities")
    conn.commit()
    # Reset AUTOINCREMENT for stable demo ids after --replace
    try:
        conn.execute("DELETE FROM sqlite_sequence WHERE name='vulnerabilities'")
        conn.commit()
    except sqlite3.Error:
        pass


def parse_semgrep(file_path: str, conn) -> int:
    if not os.path.exists(file_path):
        print(f"[!] Không tìm thấy file Semgrep: {file_path}")
        return 0

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    cursor = conn.cursor()
    count = 0
    for result in data.get("results", []):
        tool = "Semgrep (SAST)"
        severity = result.get("extra", {}).get("severity", "UNKNOWN")
        name = result.get("check_id", "Unknown Check")
        description = result.get("extra", {}).get("message", "")
        path = result.get("path", "")

        cursor.execute(
            """
            INSERT INTO vulnerabilities (tool, severity, name, description, path_or_url)
            VALUES (?, ?, ?, ?, ?)
        """,
            (tool, severity, name, description, path),
        )
        count += 1

    conn.commit()
    print(f"[+] Đã thêm {count} lỗi từ Semgrep vào database.")
    return count


def parse_zap(file_path: str, conn) -> int:
    if not os.path.exists(file_path):
        print(f"[!] Không tìm thấy file ZAP: {file_path}")
        return 0

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    cursor = conn.cursor()
    count = 0
    sites = data.get("site", [])
    for site in sites:
        for alert in site.get("alerts", []):
            tool = "OWASP ZAP (DAST)"
            severity = alert.get("riskdesc", alert.get("riskcode", "UNKNOWN"))
            name = alert.get("name", alert.get("alert", "Unknown Alert"))
            description = alert.get("desc", "")
            instances = alert.get("instances") or []
            if not instances:
                instances = [{"uri": ""}]
            # Một instance = một row (giữ evidence URL cụ thể cho demo/gộp)
            for inst in instances:
                url = (inst or {}).get("uri", "") or ""
                cursor.execute(
                    """
                    INSERT INTO vulnerabilities (tool, severity, name, description, path_or_url)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (tool, severity, name, description, url),
                )
                count += 1

    conn.commit()
    print(f"[+] Đã thêm {count} lỗi từ OWASP ZAP vào database.")
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse SAST/DAST results into Data Lake (SQLite)")
    parser.add_argument("--semgrep", type=str, help="Đường dẫn tới file JSON của Semgrep", default="semgrep-report.json")
    parser.add_argument("--zap", type=str, help="Đường dẫn tới file JSON của ZAP", default="zap-report.json")
    parser.add_argument("--db", type=str, help="Đường dẫn tới SQLite Database", default="data-lake/vuln_data.db")
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Xóa toàn bộ bảng vulnerabilities trước khi insert (seed idempotent)",
    )
    args = parser.parse_args()

    db_path = os.path.abspath(args.db)
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)

    print(f"[*] Đang sử dụng database tại: {db_path}")
    conn = init_db(db_path)
    if args.replace:
        clear_vulnerabilities(conn)
        print("[*] Đã xoá dữ liệu cũ (--replace)")

    parse_semgrep(args.semgrep, conn)
    parse_zap(args.zap, conn)

    total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    conn.close()
    print(f"[*] Hoàn tất! Tổng rows: {total}")


if __name__ == "__main__":
    main()
