# Tiến độ thực hiện dự án (Project Progress)

Dự án: **Telegram Linux Server Administration Bot**
Phương châm: *Security-First, Defense-in-Depth, Fail-Closed*

## Trạng thái các cột mốc (Milestones)

- [x] **Milestone 1: Cấu hình, Quản lý Secret & Khởi động Fail-Closed**
  - Trạng thái: Hoàn thành (11/11 tests passed)
  - Kiểm thử: `tests/test_config.py`
  - Ghi chú: Đã xây dựng schema validation nghiêm ngặt, từ chối chạy dưới quyền root, nạp token ưu tiên systemd-creds -> file -> env, kiểm tra quyền file 0600/0400 trên POSIX.

- [ ] **Milestone 2: Bộ lọc Định danh & Chống tấn công Replay**
  - Trạng thái: Chưa bắt đầu
  - Kiểm thử: `tests/test_identity.py`

- [ ] **Milestone 3: Xác thực 2 bước TOTP, Khóa tài khoản & Quản lý Session**
  - Trạng thái: Chưa bắt đầu
  - Kiểm thử: `tests/test_auth_totp.py`, `tests/test_session.py`

- [ ] **Milestone 4: Công cụ Chính sách (Policy Engine) & Xác nhận Lệnh Nguy hiểm**
  - Trạng thái: Chưa bắt đầu
  - Kiểm thử: `tests/test_policy.py`, `tests/test_confirmation.py`

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
