# Reports

Báo cáo tiến độ theo tuần cho Project Sentinel. Quy ước:

- **`week-N/report.md`** — báo cáo chính của tuần, tối đa **1 trang A4**, chia rõ 2 phần:
  **Quá trình** (đã làm gì, quyết định kỹ thuật nào) và **Kết quả** (số liệu/artefact thật, có link).
- **Đóng băng sau khi nộp.** Một khi `week-N/report.md` đã viết xong, không sửa lại nội dung để khớp
  với code mới — code trong repo có thể thay đổi tiếp, nhưng báo cáo phải giữ nguyên như một bản ghi
  lịch sử tại thời điểm nộp. Muốn cập nhật tiến độ mới thì viết report của tuần tiếp theo, hoặc thêm
  vào [`PROGRESS.md`](PROGRESS.md) (nhật ký sống, được phép cập nhật liên tục).
- **Không nhét dữ liệu thô vào report.** Số liệu/log/JSON/CSV thô là cho máy đọc — để trong
  `data-lake/` và chỉ **link** tới từ report, không copy nguyên khối vào file `.md`.
- Mỗi thư mục `week-N/` có thể có thêm tài liệu phụ (kế hoạch, chi tiết kỹ thuật) bên cạnh
  `report.md` — các file phụ này cũng được coi là hồ sơ lịch sử, không chỉnh sửa lại.

## Mục lục

| Tuần | Báo cáo chính | Ghi chú |
|---|---|---|
| 1 | [`week-1/README.md`](week-1/README.md) | Chưa có report 1-trang riêng — trỏ tới artefact gốc |
| 2 | [`week-2/report.md`](week-2/report.md) | + [`gateway-agent-iam.md`](week-2/gateway-agent-iam.md), [`plan.md`](week-2/plan.md) |
| 3 | [`week-3/report.md`](week-3/report.md) | + [`details.md`](week-3/details.md) (bản chi tiết cũ), [`plan.md`](week-3/plan.md) |

Xem thêm: [`PROGRESS.md`](PROGRESS.md) — nhật ký tiến độ toàn dự án (12 tuần, cập nhật liên tục).
[`gap-analysis-week1-3.md`](gap-analysis-week1-3.md) — đối chiếu Tuần 1-3 với đề bài gốc.
