# Reports

Báo cáo tiến độ theo tuần cho Project Sentinel. Quy ước:

- **`week-N/<ngày>_<tên>_Week<N>.md`** — báo cáo chính của tuần (giữ định dạng tên file như trước
  giờ vẫn dùng: ngày nộp, tên người nộp, số tuần — không đổi sang tên chung chung như `report.md`).
  Tối đa **1 trang A4**, chia rõ 2 phần: **Quá trình** (đã làm gì, quyết định kỹ thuật nào) và
  **Kết quả** (số liệu/artefact thật, có link).
- **Đóng băng sau khi nộp.** Một khi báo cáo của tuần đã viết xong, không sửa lại nội dung để khớp
  với code mới — code trong repo có thể thay đổi tiếp, nhưng báo cáo phải giữ nguyên như một bản ghi
  lịch sử tại thời điểm nộp. Muốn cập nhật tiến độ mới thì viết report của tuần tiếp theo, hoặc thêm
  vào [`PROGRESS.md`](PROGRESS.md) (nhật ký sống, được phép cập nhật liên tục).
- **Không nhét dữ liệu thô vào report.** Số liệu/log/JSON/CSV thô là cho máy đọc — để trong
  `data-lake/` và chỉ **link** tới từ report, không copy nguyên khối vào file `.md`.
- Mỗi thư mục `week-N/` có thể có thêm tài liệu phụ (kế hoạch, chi tiết kỹ thuật) bên cạnh báo cáo
  chính — các file phụ này cũng được coi là hồ sơ lịch sử, không chỉnh sửa lại.

## Mục lục

| Tuần | Báo cáo chính | Ghi chú |
|---|---|---|
| 1 | [`week-1/README.md`](week-1/README.md) | Chưa có report 1-trang riêng — trỏ tới artefact gốc |
| 2 | [`week-2/2026-07-31_NguyenThanhAnhQuan_Week2.md`](week-2/2026-07-31_NguyenThanhAnhQuan_Week2.md) | + [`gateway-agent-iam.md`](week-2/gateway-agent-iam.md), [`plan.md`](week-2/plan.md) |
| 3 | [`week-3/2026-08-07_NguyenThanhAnhQuan_Week3.md`](week-3/2026-08-07_NguyenThanhAnhQuan_Week3.md) | + [`details.md`](week-3/details.md) (bản chi tiết cũ), [`plan.md`](week-3/plan.md) |
| 4 | [`week-4/2026-08-15_NguyenThanhAnhQuan_Week4.md`](week-4/2026-08-15_NguyenThanhAnhQuan_Week4.md) | Nền Gateway/IAM đã làm sớm ở "week-2" (xem ghi chú lệch số tuần); report này chốt phần hoàn thiện |
| 5 | [`week-5/2026-08-19_NguyenThanhAnhQuan_Week5.md`](week-5/2026-08-19_NguyenThanhAnhQuan_Week5.md) | Guardrails / Human-in-the-Loop / che dữ liệu nhạy cảm |
| 6 | [`week-6/2026-08-19_NguyenThanhAnhQuan_Week6.md`](week-6/2026-08-19_NguyenThanhAnhQuan_Week6.md) | Tích hợp, đánh giá, thuyết trình — Docker Compose thật, eval Security Analysis Agent |

Xem thêm: [`PROGRESS.md`](PROGRESS.md) — nhật ký tiến độ toàn dự án (đề gốc **6 tuần**, cập nhật liên tục).
[`gap-analysis-week1-3.md`](gap-analysis-week1-3.md) — đối chiếu Tuần 1-3 với đề bài gốc.
