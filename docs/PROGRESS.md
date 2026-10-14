# Tiến độ thực hiện dự án (Project Progress)

Dự án: **Telegram Linux Server Administration Bot**
Phương châm: *Security-First, Defense-in-Depth, Fail-Closed*

## Trạng thái các cột mốc (Milestones)

- [x] **Milestone 1: Cấu hình, Quản lý Secret & Khởi động Fail-Closed**
  - Trạng thái: Hoàn thành (11/11 tests passed)
  - Kiểm thử: `tests/test_config.py`
  - Ghi chú: Đã xây dựng schema validation nghiêm ngặt, từ chối chạy dưới quyền root, nạp token ưu tiên systemd-creds -> file -> env, kiểm tra quyền file 0600/0400 trên POSIX.

- [x] **Milestone 2: Bộ lọc Định danh & Chống tấn công Replay**
  - Trạng thái: Hoàn thành (9/9 tests passed, tổng 20/20)
  - Kiểm thử: `tests/test_identity.py`
  - Ghi chú: Đã xây dựng bộ lọc private chat, chat_id == user_id, drop silent cho user lạ kèm rate-limited audit, chặn stale message > 60s, hủy forwarded/edited/channel/inline updates.

- [x] **Milestone 3: Xác thực 2 bước TOTP, Khóa tài khoản & Quản lý Session**
  - Trạng thái: Hoàn thành (9/9 tests passed, tổng 29/29)
  - Kiểm thử: `tests/test_auth_totp.py`, `tests/test_session.py`
  - Ghi chú: Đã xây dựng xác thực TOTP RFC 6238, độ lệch tối đa 1 bước (30s), chặn replay mã OTP, khóa tài khoản sau 5 lần sai với exponential backoff, session thuần bộ nhớ RAM với idle timeout (10 phút) và absolute timeout (1 giờ).

- [x] **Milestone 4: Công cụ Chính sách (Policy Engine) & Xác nhận Lệnh Nguy hiểm**
  - Trạng thái: Hoàn thành (12/12 tests passed, tổng 41/41)
  - Kiểm thử: `tests/test_policy.py`, `tests/test_confirmation.py`
  - Ghi chú: Đã xây dựng Policy Engine chế độ restricted (kiểm tra chặt chẽ regex/enum, triệt tiêu command injection), nhận diện mẫu lệnh nguy hiểm (rm, dd, mkfs, shutdown, iptables, pipe shell, fork bombs), cơ chế xác nhận lệnh dangerous ràng buộc SHA-256 hash, user ID, chat ID, message ID, nonce một lần và thời hạn 30 giây.

- [x] **Milestone 5: Bộ thực thi Tiến trình (Process Executor) & Quản lý Tác vụ (Jobs)**
  - Trạng thái: Hoàn thành (13/13 tests passed)
  - Kiểm thử: `tests/test_executor.py`, `tests/test_jobs_rate_limit.py`, `tests/test_terminals.py`
  - Ghi chú: Đã xây dựng bộ thực thi tiến trình cô lập process group, clean env allowlist, stream cap 1MB, timeout SIGTERM->SIGKILL, JobManager giới hạn 2 jobs đồng thời, rate limit 10 lệnh/phút/user, Gateway đa terminal (1 đến 10 terminals) hỗ trợ lệnh prefix dấu chấm (.stop, .new, .t1..10, .terminals, .close), và Core thực thi C/C++ native (`server_executor.c`).

- [x] **Milestone 6: Xử lý Làm sạch Dữ liệu (Redaction) & Nhật ký Kiểm toán (Audit)**
  - Trạng thái: Hoàn thành (9/9 tests passed, tổng 63/63)
  - Kiểm thử: `tests/test_redaction.py`, `tests/test_audit.py`
  - Ghi chú: Đã xây dựng bộ lọc ANSI escape, tự động che giấu Telegram Bot Token, Private Keys, mật khẩu key=value, Cloud Access Keys, TOTP codes; escape HTML; xuất nhật ký kiểm toán JSON Lines append-only và cảnh báo khẩn cấp tới quản trị viên qua Telegram.

- [x] **Milestone 7: Tích hợp Bot Handlers & Bản địa hóa Tiếng Việt**
  - Trạng thái: Hoàn thành (1/1 e2e test passed, tổng 64/64 tests passed)
  - Kiểm thử: `tests/test_end_to_end.py`
  - Ghi chú: Đã xây dựng `src/messages.py` với toàn bộ câu thông báo bằng tiếng Việt; triển khai các handlers `/login`, `/logout`, `/run`, `/status`, `/whoami`, `/jobs`, `/kill`, `/help`; bộ điều phối gateway đa terminal với tiền tố dấu chấm (`.stop`, `.new`, `.t1..10`, v.v.); bộ xử lý callback xác nhận lệnh nguy hiểm và cấp quyền sudo tương tác; xử lý lỗi fail-closed toàn diện; kiểm thử tích hợp end-to-end không cần mạng mô phỏng đầy đủ chu trình.

- [ ] **Milestone 8: Triển khai Cứng hóa (Hardening), Script TOTP & Tài liệu**
  - Trạng thái: Chưa bắt đầu
  - Cấu hình: `deploy/systemd/`, `deploy/sudoers.d/`, `docs/SECURITY.md`, `README.md`

- [ ] **Milestone 9: Rà soát 19 Yêu cầu Bảo mật, Kiểm thử Toàn diện & Linters**
  - Trạng thái: Chưa bắt đầu
