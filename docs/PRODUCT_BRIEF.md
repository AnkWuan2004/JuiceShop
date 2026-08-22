# Bản mô tả sản phẩm — Project Sentinel

## Vấn đề cần giải quyết

Đội bảo mật nhỏ không đủ thời gian đọc và ưu tiên hàng trăm cảnh báo SAST/DAST thô sau mỗi lần quét —
mỗi tool một định dạng, một thang mức độ nghiêm trọng khác nhau, và không tool nào tự đề xuất bước kiểm
tra tiếp theo một cách an toàn. Kết quả: cảnh báo quan trọng bị chìm giữa nhiễu, và việc xác minh thủ
công (có thật sự khai thác được không) tốn thời gian, dễ làm sai nếu chạy nhầm request vào hệ thống
ngoài phạm vi.

## Người sử dụng

- Kỹ sư AppSec/DevSecOps cần triage nhanh kết quả quét trước khi báo cáo lên mentor/khách hàng.
- Thực tập sinh học pentest an toàn trên môi trường lab (OWASP Juice Shop), có rào chắn để không lỡ tay
  chạy request nguy hiểm.
- Mentor/người đánh giá cần xem một luồng đầu-cuối rõ ràng: quét → phân tích → đề xuất → phê duyệt →
  kiểm tra thật → báo cáo.

## Giá trị sản phẩm

- **Chuẩn hóa + gộp trùng** kết quả Semgrep (SAST) và OWASP ZAP (DAST) thành một định dạng, loại trùng
  lặp giữa hai tool.
- **Security Analysis Agent** giải thích lỗ hổng bằng ngôn ngữ đơn giản, đề xuất cách khắc phục, luôn
  bám evidence thật (không bịa finding — `dropped_no_evidence = 0` trên 74 finding thật).
- **Kiểm tra an toàn có kiểm soát**: Agent đề xuất request kiểm tra → con người Approve/Reject (thấy rõ
  Endpoint/Payload/Mục đích trước khi quyết định) → request chỉ đi qua API Gateway (Kong) với allowlist,
  rate-limit, timeout.
- **Chống lạm dụng AI**: nội dung lấy từ ứng dụng bị coi là dữ liệu không tin cậy (chặn prompt
  injection), dữ liệu nhạy cảm (email/phone/token/API key/password) bị che trước khi vào LLM hoặc log.

## Phạm vi hiện tại

Đã xác minh chạy thật trên Docker Compose (Juice Shop v20.1.1 + Kong 3.6):
- CI Semgrep + ZAP → chuẩn hóa → kho tri thức nhỏ (Tuần 1-2).
- Security Analysis Agent → JSONL, evidence-based, 13/13 test (Tuần 3).
- API Gateway (Kong thật) + Python tool gửi request an toàn, rate-limit xác nhận qua burst test thật
  (Tuần 4).
- Guardrails chống prompt injection, Human-in-the-Loop Approve/Reject, che dữ liệu nhạy cảm, 23/23 test
  (Tuần 5).
- Luồng đầu-cuối thật đã chạy: 2 lỗi SQL injection xác nhận khai thác sống qua gateway (Tuần 6).

## Hạn chế

- LLM mặc định chạy **MOCK offline** (không có API key thật) — giải thích/đề xuất fix dùng fallback
  rule-based/RAG, chưa tùy biến sát từng finding như khi bật LLM thật.
- Severity đôi khi lệch với đánh giá con người trên các case biên (vd. secret trong file fixture demo bị
  đánh giá quá cao — xem `docs/RESULTS_REPORT.md`).
- Chỉ nhắm `localhost`/Docker Compose — không dùng để pentest hệ thống thật hoặc production.
- Semantic search trong kho tri thức fallback về TF-IDF khi không cấu hình vector DB thật.

## Hướng phát triển tiếp theo

1. Bật LLM thật, đánh giá lại chất lượng giải thích/đề xuất fix so với fallback MOCK.
2. Thêm rule nâng/hạ severity theo ngữ cảnh (secret trong fixture vs production, hardcoded signing key).
3. Mở rộng bộ eval từ 8 lên toàn bộ finding, có sự tham gia của nhiều người chấm để giảm thiên lệch chủ quan.
4. Nối các cơ chế Guardrails/HITL/che dữ liệu vào live demo web (hiện chỉ chạy CLI cục bộ).
