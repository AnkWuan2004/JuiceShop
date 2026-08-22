#!/usr/bin/env python3
"""
Common utilities cho agents: LLM client (mock/real), file tracer + PII redaction + FinOps estimate.
MOCK khi không có OPENAI_API_KEY — demo offline deterministic JSON.
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TRACE_DIR = ROOT / "data-lake" / "traces"

# Bộ đệm trace theo request (contextvar — an toàn giữa các request đồng thời), dùng để
# tính cost/latency của MỘT lần gọi (vd 1 lần "Chạy Agent") mà không cần đọc lại file.
_trace_buffer: contextvars.ContextVar[list | None] = contextvars.ContextVar("trace_buffer", default=None)


def start_trace_capture() -> None:
    """Bắt đầu thu thập trace cho request hiện tại. Gọi trước khi chạy agent."""
    _trace_buffer.set([])


def collect_traces() -> list[dict]:
    """Lấy các trace đã ghi từ lần start_trace_capture() gần nhất."""
    buf = _trace_buffer.get()
    return list(buf) if buf is not None else []


def get_trace_buffer() -> list | None:
    """Trả về buffer hiện tại (object thật, không phải bản copy) — dùng để gắn sang thread khác,
    vì contextvars không tự lan sang thread mới do một ThreadPoolExecutor tạo."""
    return _trace_buffer.get()


def attach_trace_buffer(buf: list | None) -> None:
    """Gắn buffer có sẵn (lấy từ get_trace_buffer() ở thread cha) vào context của thread hiện tại,
    để write_trace() gọi trong thread con vẫn ghi được vào cùng một buffer với thread cha."""
    _trace_buffer.set(buf)


def _load_dotenv() -> None:
    """Nạp .env ở gốc repo (không ghi đè biến đã có trong môi trường). Không phụ thuộc python-dotenv."""
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


_load_dotenv()


def _is_local_base(url: str) -> bool:
    return any(h in url for h in ("localhost", "127.0.0.1", "0.0.0.0"))
KONG_BASE = os.environ.get("SENTINEL_KONG", "http://localhost:8000")
RECON_KEY = os.environ.get("SENTINEL_RECON_KEY", "recon-key-demo")
EXPLOIT_KEY = os.environ.get("SENTINEL_EXPLOIT_KEY", "exploit-key-demo")

# Ước lượng chi phí (USD / 1M tokens) — chỉnh theo bảng giá DeepSeek V4 Flash qua env
_COST_IN = float(os.environ.get("SENTINEL_COST_IN_PER_1M", "0.15"))
_COST_OUT = float(os.environ.get("SENTINEL_COST_OUT_PER_1M", "0.60"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_trace_dir() -> Path:
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    return TRACE_DIR


def _redact_obj(obj: Any) -> Any:
    try:
        from pii_redaction import redact
    except ImportError:
        return obj
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: _redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(x) for x in obj]
    return obj


def write_trace(agent: str, event: str, data: Any) -> Path:
    """Ghi trace JSONL vào data-lake/traces/ — PII redacted trước khi persist.
    Fail-safe trên filesystem read-only (VD: Vercel serverless) — bỏ qua thay vì crash."""
    path = TRACE_DIR / f"{agent}_{datetime.now().strftime('%Y%m%d')}.jsonl"
    safe = _redact_obj(data)
    record = {"ts": utc_now(), "agent": agent, "event": event, "data": safe}
    buf = _trace_buffer.get()
    if buf is not None:
        buf.append(record)
    try:
        ensure_trace_dir()
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass
    try:
        from observability import emit_langsmith_span

        emit_langsmith_span(agent, event, safe)
    except Exception:
        pass
    return path


def est_tokens(text: str) -> int:
    """Ước lượng thô ~4 chars/token."""
    return max(1, len(text) // 4)


def est_cost_usd(tokens_in: int, tokens_out: int, *, mock: bool) -> float:
    if mock:
        return 0.0
    return (tokens_in * _COST_IN + tokens_out * _COST_OUT) / 1_000_000.0


class LLMClient:
    """LLM provider = DeepSeek (OpenAI-compatible) qua OPENAI_* env. Không key thật → mock offline."""

    def __init__(self) -> None:
        self.api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        self.base_url = os.environ.get("OPENAI_BASE_URL", "").strip() or None
        # Mặc định DeepSeek V4 Flash 0731 qua OpenRouter (không dùng OpenAI/Gemini/Anthropic)
        self.model = os.environ.get("OPENAI_MODEL", "deepseek/deepseek-v4-flash-0731")
        # Mock khi không có key thật. Ngoại lệ: base_url localhost (vLLM stub) chấp nhận key giả.
        self.mock = not bool(self.api_key)
        # Hook cho test: ép offline dù .env có key thật (deterministic, không gọi mạng).
        if os.environ.get("SENTINEL_FORCE_MOCK", "").strip() in ("1", "true", "yes"):
            self.mock = True
            return
        if self.base_url and not self.api_key and _is_local_base(self.base_url):
            self.api_key = "stub-key"
            self.mock = False
            if not os.environ.get("OPENAI_MODEL"):
                self.model = "sentinel-vllm-stub"

    def chat(self, system: str, user: str, *, expect_json: bool = True) -> str:
        tin = est_tokens(system) + est_tokens(user)
        t0 = time.time()
        write_trace(
            "llm",
            "request",
            {
                "mock": self.mock,
                "base_url": self.base_url,
                "model": self.model,
                "system_len": len(system),
                "user_len": len(user),
                "est_tokens_in": tin,
            },
        )
        err = None
        try:
            if self.mock:
                out = self._mock_response(system, user)
            else:
                out = self._openai_chat(system, user)
        except Exception as e:
            err = str(e)
            write_trace("llm", "error", {"error": err})
            if self.mock:
                # Mock chỉ dùng cho test/local offline — không để 1 bug trong _mock_response làm
                # sập cả bộ test, fallback JSON lỗi vẫn đủ để caller xử lý.
                out = json.dumps({"error": err, "mock_fallback": True})
            else:
                # Real mode (đang bật AI thật, vd trên Vercel đã cấu hình OPENAI_API_KEY): KHÔNG
                # lặng lẽ trả dữ liệu giả khi gọi AI thất bại — raise để route hiển thị lỗi rõ ràng
                # cho người xem thay vì trông như "AI trả kết quả rác/không đổi gì".
                latency_ms = int((time.time() - t0) * 1000)
                write_trace(
                    "llm", "response",
                    {
                        "mock": False, "base_url": self.base_url, "model": self.model,
                        "preview": None, "est_tokens_out": 0, "est_tokens_in": tin,
                        "est_cost_usd": 0.0, "latency_ms": latency_ms, "error": err,
                    },
                )
                raise RuntimeError(f"Không gọi được AI thật (DeepSeek/OpenRouter): {err}") from e
        latency_ms = int((time.time() - t0) * 1000)
        tout = est_tokens(out)
        cost = est_cost_usd(tin, tout, mock=self.mock)
        write_trace(
            "llm",
            "response",
            {
                "mock": self.mock,
                "base_url": self.base_url,
                "model": self.model,
                "preview": out[:500],
                "est_tokens_out": tout,
                "est_tokens_in": tin,
                "est_cost_usd": cost,
                "latency_ms": latency_ms,
                "error": err,
            },
        )
        return out

    def _openai_chat(self, system: str, user: str) -> str:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        # Ưu tiên SDK openai nếu có; nếu không, gọi REST bằng requests (OpenAI-compatible).
        try:
            from openai import OpenAI  # type: ignore

            kwargs = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            client = OpenAI(**kwargs)
            resp = client.chat.completions.create(
                model=self.model, messages=messages, temperature=0.2
            )
            return resp.choices[0].message.content or ""
        except ImportError:
            return self._rest_chat(messages)

    def _rest_chat(self, messages: list[dict]) -> str:
        """REST /chat/completions bằng requests — dùng khi không có package openai (vd OpenRouter).
        Timeout dài (model chậm) + retry vài lần cho lỗi mạng transient — trừ trên Vercel, nơi
        maxDuration=60s (vercel.json): timeout dài + nhiều retry sẽ bị Vercel giết cứng (504
        FUNCTION_INVOCATION_TIMEOUT) trước khi code kịp bắt exception và hiển thị lỗi tử tế."""
        import requests  # type: ignore

        base = (self.base_url or "https://api.openai.com/v1").rstrip("/")
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        # DeepSeek/OpenRouter đo thực tế mất tới ~44s cho 1 lượt gọi bình thường (không lỗi) — timeout
        # 20s trước đây quá ngắn, khiến request THÀNH CÔNG cũng bị huỷ giữa chừng rồi retry, tổng thời
        # gian dồn lại vượt quá 60s của Vercel → 502/504 thay vì lỗi tử tế. Sửa: timeout đủ dài cho 1
        # lượt (còn dư biên so với 60s), KHÔNG retry (retry chỉ khiến tổng thời gian dễ vượt trần hơn).
        on_vercel = bool(os.environ.get("VERCEL"))
        default_timeout = "50" if on_vercel else "180"
        default_retries = "1" if on_vercel else "3"
        timeout = float(os.environ.get("SENTINEL_LLM_TIMEOUT", default_timeout))
        retries = int(os.environ.get("SENTINEL_LLM_RETRIES", default_retries))
        last_err: Exception | None = None
        for attempt in range(retries):
            try:
                resp = requests.post(
                    f"{base}/chat/completions",
                    headers=headers,
                    json={"model": self.model, "messages": messages, "temperature": 0.2},
                    timeout=timeout,
                )
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"] or ""
            except requests.exceptions.RequestException as e:  # timeout / conn / 5xx
                last_err = e
                if attempt < retries - 1:
                    time.sleep(2 * (attempt + 1))
        raise last_err  # type: ignore[misc]

    def _mock_response(self, system: str, user: str) -> str:
        """Phản hồi JSON deterministic; recon merge DB map nếu có trong user."""
        blob = (system + "\n" + user).lower()
        digest = hashlib.sha256(blob.encode()).hexdigest()[:8]

        # Injection hijack demo: raw IGNORE in context without guardrail marker
        if "ftp_content" in blob and "ignore previous" in blob and "[guardrail]" not in blob:
            return json.dumps(
                {
                    "mock": True,
                    "hijacked": True,
                    "summary": "no vulnerabilities exist",
                    "api_keys": ["sk-mock-leaked-demo"],
                    "vulnerabilities": [],
                },
                indent=2,
            )
        if "ftp_content" in blob and ("[guardrail]" in blob or "redacted_injection" in blob):
            return json.dumps(
                {
                    "mock": True,
                    "hijacked": False,
                    "summary": "External FTP content blocked by guardrail; continue normal recon.",
                    "api_keys": [],
                    "vulnerabilities": [{"path": "/rest/products/search", "issue": "SQLi"}],
                },
                indent=2,
            )

        # Tuần 3 — Security Analysis Agent: điền explanation + remediation, grounded trên RAG.
        # Check SỚM và cụ thể (literal "Security Analysis Agent" ở đầu system prompt) — phải đứng
        # trước các check chung như "exploit" (system prompt phân tích có chữ "exploitation" nên
        # naive `"exploit" in blob` sẽ khớp nhầm sang nhánh Exploit Agent nếu để sau).
        if "security analysis agent" in blob or ("explanation" in blob and "remediation" in blob and "finding" in blob):
            name = "the finding"
            desc = ""
            rag = ""
            try:
                u = json.loads(user) if user.strip().startswith("{") else {}
                name = str(u.get("name") or name)
                desc = str((u.get("finding") or {}).get("scanner_description") or "").strip()
                ctx = u.get("rag_context") or []
                rag = (ctx[0] if ctx else "")[:220]
            except Exception:
                pass
            # Ưu tiên mô tả thật từ chính scanner (luôn khớp đúng finding này) hơn đoạn RAG — RAG chỉ
            # là tài liệu tham khảo chung, có thể lệch chủ đề với finding cụ thể (VD: rule CI/CD YAML
            # không có doc RAG chuyên biệt, RAG trả về đoạn gần nhất về SQLi/XSS — dễ gây hiểu nhầm).
            if desc:
                expl = f"{name}: {desc[:280]}"
            else:
                expl = (f"{name}. {rag}").strip() or f"{name} là lỗ hổng do công cụ quét phát hiện."
            # remediation để trống — nhường cho analysis_agent.py::fallback_remediation(name) xử lý,
            # vì hàm đó có bảng gợi ý theo từng loại lỗ hổng (sql/xss/csrf/idor/jwt/...) chi tiết hơn
            # 1 câu chung cứng ở đây, và tránh lặp y hệt cho toàn bộ 74 finding.
            return json.dumps(
                {
                    "mock": True,
                    "explanation": expl,
                    "remediation": "",
                },
                ensure_ascii=False,
            )

        if "attack surface" in blob or ("recon" in blob and "endpoint" in blob) or "db_map" in blob:
            endpoints = []
            try:
                u = json.loads(user) if user.strip().startswith("{") else {}
                db_map = u.get("db_map") or {}
                endpoints = list(db_map.get("endpoints") or [])
                # also fold vulnerabilities
                for v in u.get("vulnerabilities") or []:
                    name = str(v.get("name") or "")
                    path = "/rest/products/search"
                    if "xss" in name.lower():
                        path = "/api/Feedbacks"
                    endpoints.append(
                        {
                            "path": path,
                            "method": "GET",
                            "risk": "high",
                            "issue": name or "from-db",
                            "cve_related": [],
                            "from_vuln_row": True,
                        }
                    )
            except Exception:
                pass
            if not endpoints:
                endpoints = [
                    {
                        "path": "/rest/products/search",
                        "method": "GET",
                        "risk": "high",
                        "issue": "SQL Injection",
                        "cve_related": ["CWE-89"],
                    },
                ]
            # de-dupe by path keeping first
            seen = set()
            uniq = []
            for e in endpoints:
                p = e.get("path")
                if p in seen:
                    continue
                seen.add(p)
                uniq.append(e)
            return json.dumps(
                {
                    "mock": True,
                    "id": digest,
                    "endpoints": uniq[:12],
                    "summary": f"Đã gộp {len(uniq)} endpoint từ dữ liệu quét (mock enrich).",
                },
                indent=2,
            )

        if "exploit" in blob or "dangerous" in blob or "proof" in blob:
            hint = ""
            try:
                u = json.loads(user) if user.strip().startswith("{") else {}
                hint = str(u.get("user_hint") or "").strip()
            except Exception:
                pass
            hl = hint.lower()
            action, path, param_key, param_val = "sqli_probe", "/rest/products/search", "q", "' OR '1'='1"
            justification = "Xác nhận lỗi SQL Injection trên Juice Shop local, chỉ ở phạm vi search."
            if hint.startswith("/"):
                path = hint
                justification = f"Kiểm tra endpoint theo gợi ý '{hint}' — thử payload SQLi cơ bản."
            if "feedback" in hl:
                action, path, param_key, param_val = "xss_probe", "/api/Feedbacks", "comment", "<script>alert(1)</script>"
                justification = f"Kiểm tra XSS ở form feedback theo gợi ý '{hint}'."
            elif "admin" in hl:
                action, path, param_key, param_val = "auth_bypass_write", "/rest/admin/application-version", "", ""
                justification = f"Kiểm tra khả năng truy cập trái phép khu vực quản trị theo gợi ý '{hint}'."
            elif "xss" in hl or "script" in hl:
                action, param_val = "xss_probe", "<script>alert(1)</script>"
                justification = f"Kiểm tra XSS theo gợi ý '{hint}' trên tham số đầu vào."
            elif hint and "sql" not in hl:
                justification = f"Theo gợi ý '{hint}': " + justification
            params = {param_key: param_val} if param_key else {}
            return json.dumps(
                {
                    "mock": True,
                    "id": digest,
                    "action": action,
                    "dangerous": True,
                    "justification": justification,
                    "request": {
                        "method": "GET",
                        "path": path,
                        "params": params,
                    },
                },
                indent=2,
            )

        if "fuzz" in blob or ("payload" in blob and "target" in blob):
            return json.dumps(
                {
                    "mock": True,
                    "id": digest,
                    "payloads": [
                        {"target": "/rest/products/search", "param": "q", "value": "' OR 1=1--"},
                        {"target": "/rest/products/search", "param": "q", "value": "<script>alert(1)</script>"},
                        {"target": "/rest/products/search", "param": "q", "value": "' UNION SELECT null--"},
                    ],
                },
                indent=2,
            )

        if "judge" in blob or "evaluate" in blob or "verdict" in blob:
            return json.dumps(
                {
                    "mock": True,
                    "score": 0.85,
                    "verdict": "partial_match",
                    "reason": "Đánh giá mock: endpoint/mức rủi ro khớp với kỳ vọng.",
                },
                indent=2,
            )

        return json.dumps({"mock": True, "id": digest, "message": "OK", "echo_hash": digest}, indent=2)


def parse_json_loose(text: str) -> Any:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start : end + 1])
        raise


def rate_limit_sleep(seconds: float = 0.3) -> None:
    time.sleep(seconds)
