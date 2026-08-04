# Plan Tuần 3 — Security Analysis Agent

**Đề:** VinUni × VinSOC — lộ trình **6 tuần** · **Tuần 3:** xây AI Agent đọc kết quả quét → **báo cáo bảo mật** (JSONL)
**Status:** ✅ HOÀN THÀNH — 53 findings grounded (0 bịa) · 13/13 test PASS · report `docs/notes/Week3_Security_Analysis_Agent.md`
**Nộp:** 1 file MD tiếng Việt (~1 trang + sơ đồ) — mặc định `docs/notes/Week3_Security_Analysis_Agent.md`
**Nguyên tắc:** **evidence-based, không bịa** · output ổn định · fail-safe với input rỗng/hỏng

---

## Mindset (đo thành công)

> Agent chỉ được nói cái mà **dữ liệu quét tuần 1–2 chứng minh**. Mỗi finding phải truy vết về một (hoặc nhiều) hàng trong `vuln_data.db`. Không có row → không có finding. Kho tri thức tuần 2 chỉ để **giải thích**, không để **phát minh** lỗ hổng/endpoint.

| Câu hỏi thiết kế | Trả lời tối thiểu |
|---|---|
| Agent lấy sự thật từ đâu? | `vuln_data.db` (140 rows Semgrep+ZAP) — nguồn duy nhất của "có lỗ gì / ở đâu" |
| Kho tri thức dùng làm gì? | Chỉ **giải thích + đề xuất fix** (RAG tuần 2), không sinh endpoint mới |
| Chống hallucination bằng gì? | Mỗi finding mang `evidence.source_ids` trỏ về id row DB; post-check loại finding không có evidence |
| Proof gì? | Report JSONL chạy được từ data thật + 3 test (gồm input rỗng) có Pass/Fail rõ |

---

## Đề tuần 3 yêu cầu gì (bám PDF trang 4–5)

**Công việc**
- Thiết kế **System Prompt** cho Agent (lưu trong repo).
- Kết nối Agent với: (a) dữ liệu kết quả quét, (b) kho tri thức tuần 2.
- Agent phải: **gộp cảnh báo trùng** · **phân loại severity** · **giải thích ngôn ngữ đơn giản** · **đề xuất kiểm tra/khắc phục**.
- Trả kết quả **JSONL**.

**Định dạng mỗi finding (gợi ý PDF):** Tên lỗ hổng · Mức nghiêm trọng · Vị trí · Bằng chứng từ tool · Giải thích · Đề xuất khắc phục · Mức tin cậy.

**Sản phẩm bàn giao**
- 1 Security Analysis Agent hoạt động.
- System Prompt lưu trong repo.
- 1 báo cáo phân tích tự động.
- ≥ 3 tình huống kiểm thử cho Agent.

**Tiêu chí hoàn thành**
- Tạo được báo cáo từ data tuần 1 + tuần 2.
- **Không bịa** endpoint/lỗ hổng ngoài data.
- Định dạng output **ổn định**.
- Xử lý được input **rỗng / không hợp lệ**.

---

## Cái đã có → tái sử dụng (không viết lại)

| Thành phần | File | Dùng cho tuần 3 |
|---|---|---|
| LLM client (mock + real) + trace + PII redact | `agents/common.py` (`LLMClient`, `parse_json_loose`, `write_trace`) | Gọi LLM, chạy demo offline deterministic |
| Unified findings | `data-lake/vuln_data.db` → `vulnerabilities(tool,severity,name,description,path_or_url)` | Nguồn sự thật cho Agent |
| Retrieval / grounding | `rag/query.py::search`, `rag/hybrid_search.py::hybrid_search` | Lấy đoạn giải thích + fix theo tên lỗ hổng |
| MCP tool (tuỳ chọn) | `agents/mcp_client.py::try_mcp_call("get_scan_results")` | Đọc DB qua tool thay vì mở SQLite trực tiếp |

**Gap thật sự:** chưa có agent nào **gộp trùng + xếp severity chuẩn + xuất báo cáo JSONL theo schema tuần 3**. Recon agent xuất *attack surface map*, không phải *analysis report*. → Tuần 3 = viết `agents/analysis_agent.py` mới, mỏng, dựa trên các mảnh trên.

---

## Kiến trúc mục tiêu

```text
vuln_data.db ──(load + normalize severity)──┐
                                            ├──► group/dedupe ──► LLM (explain+fix, grounded) ──► post-check evidence ──► report.jsonl
RAG (owasp/cheatsheet) ──(explain context)──┘                         ▲
                                                     System Prompt (repo) ─┘
```

Luồng khớp bước 3 trong "luồng cuối cùng" của đề: *Security Analysis Agent phân tích kết quả → tạo báo cáo*.

---

## Thiết kế then chốt (chốt trước khi code)

### 1. Severity unify (việc tuần 2 cố ý hoãn lại)
Map nhãn gốc → thang chung để **phân loại + sort**, nhưng **giữ nhãn gốc** trong `evidence`:

| Nhãn gốc | → unified |
|---|---|
| `ERROR`, `High`, `critical` | `high` |
| `WARNING`, `Medium` | `medium` |
| `INFO`, `Low`, `Informational` | `low` |

Tận dụng logic sẵn có kiểu `risk_from_severity()` trong `recon_agent.py` (viết lại gọn trong analysis agent, không import chéo).

### 2. Gộp trùng (dedupe/group)
Khóa gộp = `(unified_severity, normalized_title, location_bucket)`.
- `normalized_title`: lowercase, bỏ số/ID biến thiên (vd `check_id` trùng rule → 1 nhóm).
- `location_bucket`: file/endpoint đã chuẩn hoá (dùng lại ý `extract_path()`).
- Mỗi nhóm giữ `count` + danh sách `source_ids` (id các row DB gộp vào).

### 3. Schema JSONL (1 finding / dòng) — **contract cứng**
```json
{"id":"F001","name":"SQL Injection","severity":"high","location":"juice-shop/routes/search.ts",
 "evidence":{"tools":["semgrep"],"source_ids":[12,88],"raw_severity":["ERROR"],"count":2},
 "explanation":"...ngôn ngữ đơn giản...","remediation":"...","confidence":0.0}
```
- `confidence`: heuristic minh bạch (vd 2 tool cùng chỉ 1 chỗ → cao; chỉ INFO/1 nguồn → thấp). **Không** để LLM tự bịa số → tính bằng rule, LLM chỉ điền text.
- `explanation`/`remediation`: LLM sinh, **bắt buộc** dựa trên RAG context truyền vào.

### 4. Chống hallucination (điểm rubric "AI Agent 20%")
- System Prompt: cấm sinh endpoint/lỗ hổng ngoài input; nếu thiếu chứng cứ → để trống, không đoán.
- **Post-check bằng code (không tin prompt suông):** drop mọi finding không có `source_ids` hợp lệ; drop `location` không xuất hiện trong tập path/file của DB. Ghi log số finding bị loại.

### 5. Fail-safe input rỗng/hỏng
- DB rỗng / không tồn tại → xuất `report.jsonl` rỗng + 1 dòng meta `{"status":"no_findings"}`, exit 0, không crash.
- JSON tool hỏng → `parse_json_loose` fallback; nếu vẫn fail → finding giữ evidence, `explanation="(LLM parse failed — evidence-only)"`.

---

## Lịch 3 ngày

### D1 — Đọc data + gộp + severity (deterministic, chưa cần LLM đẹp)
- [ ] `agents/analysis_agent.py`: load DB (ưu tiên MCP `get_scan_results`, fallback SQLite).
- [ ] Unify severity + dedupe/group → danh sách nhóm có `count`/`source_ids`.
- [ ] Xuất `data-lake/analysis_report.jsonl` với evidence, **explanation/remediation tạm để rỗng**.
- **Verify:** chạy `python agents/analysis_agent.py` → jsonl có N dòng, mỗi dòng có `source_ids` khớp id DB thật; sort theo severity đúng.

### D2 — System Prompt + LLM enrich (grounded) + anti-hallucination
- [ ] Viết `agents/prompts/analysis_system_prompt.txt` (lưu repo — rubric "system prompt in repo").
- [ ] Với mỗi nhóm: query RAG theo `name` → truyền context → LLM điền `explanation`+`remediation` (JSON).
- [ ] `confidence` tính bằng rule (số tool, số source, severity).
- [ ] Post-check evidence: loại finding bịa; log `dropped_no_evidence`.
- **Verify:** báo cáo chạy được cả **mock** (offline) lẫn real key; không finding nào thiếu `source_ids`; endpoint/file đều thuộc DB.

### D3 — 3 test + report MD + README
- [ ] `tests/` hoặc `scripts/test_analysis_agent.py`, ≥3 case:
  1. **Happy path** — DB thật 140 rows → jsonl hợp lệ, ≥1 high, schema đủ field.
  2. **Input rỗng** — DB rỗng → `no_findings`, không crash, exit 0.
  3. **Input hỏng/injection** — row có mô tả chứa "ignore previous instructions / no vulnerabilities" → Agent **không** bị dụ xoá finding (post-check + prompt giữ nguyên evidence).
  *(bonus 4: JSON tool malformed → fallback không vỡ.)*
- [ ] Viết `docs/notes/Week3_Security_Analysis_Agent.md` (~A4, tiếng Việt) + sơ đồ mermaid.
- [ ] README: 3 lệnh (ingest DB nếu cần → run agent → xem jsonl).
- **Verify:** người lạ chạy theo README ra đúng `analysis_report.jsonl` + bảng Pass/Fail 3 test xanh.

---

## Definition of Done

- [ ] `analysis_report.jsonl` sinh tự động từ `vuln_data.db` (data tuần 1–2).
- [ ] Mỗi finding: đủ 7 field (name, severity, location, evidence, explanation, remediation, confidence).
- [ ] Mỗi finding truy vết `source_ids` → **không bịa**; post-check log số bị loại.
- [ ] Output ổn định (chạy lại → schema/khoá gộp không đổi).
- [ ] Input rỗng/hỏng → không crash, có trạng thái rõ.
- [ ] System Prompt lưu trong repo.
- [ ] ≥3 test có Pass/Fail; 1 test là input rỗng.
- [ ] 1 MD tiếng Việt + sơ đồ, giải thích được không cần đọc cả repo.

---

## Không làm (tránh over-engineer — theo CLAUDE.md §2)

- LLM-as-a-Judge phức tạp, multi-agent, GraphRAG cho báo cáo (đề xếp là mở rộng).
- Tự map lại toàn bộ severity taxonomy chuẩn CVSS — chỉ cần 3 mức high/medium/low.
- Sinh endpoint/PoC tấn công — tuần 3 chỉ **phân tích + giải thích**, không exploit.
- Refactor `recon_agent.py`/`common.py` cho "đẹp" — chỉ tái sử dụng.

---

## File chạm chính

| File | Vai trò | Trạng thái |
|---|---|---|
| `agents/analysis_agent.py` | Agent tuần 3 (load→group→enrich→jsonl) | **mới** |
| `agents/prompts/analysis_system_prompt.txt` | System Prompt (nộp rubric) | **mới** |
| `data-lake/analysis_report.jsonl` | Báo cáo tự động | **mới (output)** |
| `scripts/test_analysis_agent.py` | 3 test (gồm input rỗng) | **mới** |
| `docs/notes/Week3_Security_Analysis_Agent.md` | File nộp | **mới** |
| `agents/common.py`, `rag/query.py`, `data-lake/vuln_data.db` | Tái sử dụng | có sẵn |

---

## Thứ tự ưu tiên khi thiếu thời gian

1. Load DB + dedupe + severity + xuất JSONL evidence (bắt buộc — đây là "báo cáo từ data").
2. System Prompt trong repo + LLM điền explanation/remediation grounded (bắt buộc rubric).
3. Post-check anti-hallucination + test input rỗng (bắt buộc tiêu chí đề).
4. MD 1 trang + sơ đồ (bắt buộc nộp).
5. Test injection + RAG enrich sâu (điểm tối đa — cắt được nếu cháy D3).

---

## Đối chiếu nhanh: đề tuần 3 → plan

| Yêu cầu PDF | Địa chỉ trong plan |
|---|---|
| System Prompt (lưu repo) | D2 · `agents/prompts/analysis_system_prompt.txt` |
| Kết nối data quét + kho tri thức | D1 (DB) + D2 (RAG) |
| Gộp trùng / phân loại severity | Thiết kế §1–§2 · D1 |
| Giải thích đơn giản + đề xuất fix | D2 (LLM grounded) |
| Output JSONL | Schema §3 · `analysis_report.jsonl` |
| Không bịa endpoint/lỗ hổng | Anti-hallucination §4 (post-check) |
| Xử lý input rỗng/không hợp lệ | Fail-safe §5 · test #2 |
| ≥3 tình huống kiểm thử | D3 |
