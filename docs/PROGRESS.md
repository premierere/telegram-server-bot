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

- [ ] **Milestone 5: Bộ thực thi Tiến trình (Process Executor) & Quản lý Tác vụ (Jobs)**
  - Trạng thái: Chưa bắt đầu
  - Kiểm thử: `tests/test_executor.py`, `tests/test_jobs_rate_limit.py`

- [ ] **Milestone 6: Xử lý Làm sạch Dữ liệu (Redaction) & Nhật ký Kiểm toán (Audit)**
  - Trạng thái: Chưa bắt đầu
  - Kiểm thử: `tests/test_redaction.py`, `tests/test_audit.py`

- [ ] **Milestone 7: Tích hợp Bot Handlers & Bản địa hóa Tiếng Việt**
  - Trạng thái: Chưa bắt đầu
  - Kiểm thử: `tests/test_end_to_end.py`

- [ ] **Milestone 8: Triển khai Cứng hóa (Hardening), Script TOTP & Tài liệu**
  - Trạng thái: Chưa bắt đầu
  - Cấu hình: `deploy/systemd/`, `deploy/sudoers.d/`, `docs/SECURITY.md`, `README.md`

- [ ] **Milestone 9: Rà soát 19 Yêu cầu Bảo mật, Kiểm thử Toàn diện & Linters**
  - Trạng thái: Chưa bắt đầu
