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

- [x] **Milestone 8: Triển khai Cứng hóa (Hardening), Script TOTP & Tài liệu**
  - Trạng thái: Hoàn thành (1/1 test passed, tổng 65/65 tests passed)
  - Kiểm thử: `tests/test_setup_totp.py`
  - Ghi chú: Đã xây dựng `scripts/setup_totp.py` sinh mã TOTP offline an toàn; unit systemd `deploy/systemd/telegram-server-bot.service` với đầy đủ cờ bảo vệ sandbox nghiêm ngặt (`ProtectSystem=strict`, `CapabilityBoundingSet=` rỗng, `LoadCredential`, v.v.); mẫu `deploy/sudoers.d/telegram-bot` phân quyền exact-match không wildcard; tài liệu `deploy/CREDENTIALS.md`; tài liệu `docs/SECURITY.md` (mô hình đe dọa, ma trận 19 yêu cầu bảo mật, kịch bản ứng phó rò rỉ token) và `README.md` hướng dẫn sử dụng và triển khai chi tiết bằng tiếng Việt.

- [x] **Milestone 9: Rà soát 19 Yêu cầu Bảo mật, Kiểm thử Toàn diện & Linters**
  - Trạng thái: Hoàn thành (65/65 tests passed, 0 lint errors, 0 security issues)
  - Công cụ: `pytest`, `ruff check`, `bandit`
  - Ghi chú: Toàn bộ 65 unit & integration tests vượt qua 100%; linter Ruff kiểm tra đạt chuẩn chất lượng mã nguồn; Bandit quét bảo mật 0 lỗ hổng nghiêm trọng; xác nhận hoàn toàn không có secret/token nào bị lộ trong codebase và logs.

- [x] **Milestone 10: Shell Tương tác Dòng lệnh (Interactive Line-by-Line Shell) & Đa Terminal PTY**
  - Trạng thái: Hoàn thành (80/80 tests passed, 0 lint errors, 0 security issues)
  - Kiểm thử: `tests/test_auth_state.py`, `tests/test_pam_verifier.py`, `tests/test_pty_session.py`, `tests/test_slash_terminals.py`, `tests/test_direct_execution.py`, `tests/test_end_to_end.py`
  - Ghi chú:
    - Loại bỏ tiền tố `/run`, cho phép gửi lệnh trực tiếp vào shell terminal đang hoạt động.
    - Quy trình xác thực nhiều bước an toàn: `/login <TOTP>` -> Nhập tài khoản Linux -> Nhập mật khẩu Linux.
    - Zero persistent storage: Mật khẩu xác thực trực tiếp qua Linux PAM (`su`), xóa tin nhắn mật khẩu tức thì trên Telegram, không ghi ra đĩa hay lưu trong RAM.
    - Cơ chế thử sai 5 lần: Nhập sai mật khẩu < 5 lần cho phép nhập lại, sai liên tiếp 5 lần tự động lùi về bước nhập tài khoản Linux.
    - Quản lý tối đa 10 terminal ảo độc lập, mỗi terminal có thể chạy dưới một tài khoản Linux riêng biệt (ví dụ `root`, `guest`).
    - Lệnh `/new`: Mở terminal cho tài khoản hiện tại không cần mật khẩu. Lệnh `/new <user>`: Yêu cầu mật khẩu của user trước khi cấp terminal.
    - Chuyển toàn bộ điều khiển terminal sang slash commands (`/stop`, `/new [user]`, `/t1`..`/t10`, `/terminals`, `/close`).
    - Định dạng prompt terminal phản ánh trạng thái thực: `Terminal<N> - <thời gian đăng nhập>\n<prompt pty>`.
    - Phân định rõ ràng: `/logout` (đóng terminal, giữ session TOTP, về bước nhập user) và `/exit` (thoát hoàn toàn, xóa phiên).

