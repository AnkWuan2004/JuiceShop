# Week 1 — Môi trường & quét bảo mật cơ bản

**Trạng thái tài liệu:** chưa có báo cáo 1-trang riêng cho Tuần 1 khi các tuần sau bắt đầu dùng quy
ước `reports/week-N/report.md`. Không dựng lại/hồi tố một báo cáo cho đúng khuôn — mục này chỉ trỏ
thẳng tới các artefact thật đã tạo ra trong Tuần 1, để không có khoảng trống trong tiến độ.

## Quá trình

- Dựng staging bằng Docker Compose (`docker-compose.yml`): OWASP Juice Shop v20.1.1 + Kong.
- Cấu hình CI quét bảo mật tự động: [`.github/workflows/security-scan.yml`](../../.github/workflows/security-scan.yml)
  (Semgrep SAST + OWASP ZAP DAST baseline, chạy mỗi push/PR vào `main`).
- Khảo sát thủ công bề mặt tấn công của Juice Shop (endpoint, auth, business logic REST API).

## Kết quả

- CI pipeline SAST + DAST chạy xanh, artefact quét lưu tại `data-lake/reports/` và
  `data-lake/ci-artifacts/`.
- Bản đồ bề mặt tấn công: [`docs/notes/ATTACK_SURFACE.md`](../../docs/notes/ATTACK_SURFACE.md).

## Dữ liệu thô / máy đọc

- `data-lake/reports/semgrep-report.json`
- `data-lake/ci-artifacts/zap-scan-report/`
