# Tài liệu Chính sách Bảo mật (Security Policy & Architecture)

Dự án **Telegram Linux Server Administration Bot** được thiết kế với tư duy phòng thủ theo chiều sâu (**Defense-in-Depth**), đối mặt với các điều kiện thù địch (**Hostile Conditions First**), tuân thủ nguyên tắc từ chối an toàn (**Fail-Closed**) và quyền hạn tối thiểu (**Least Privilege**).

---

## 1. Mô hình Đe dọa (Threat Model) & Phân tích Rủi ro

Một bot Telegram cho phép thực thi lệnh máy chủ là tính năng **Remote Code Execution (RCE) theo chủ đích**. Mọi thông điệp gửi đến đều được coi là **không đáng tin cậy (Untrusted)** cho đến khi vượt qua toàn bộ các lớp kiểm tra danh tính, xác thực hai bước, ủy quyền và chính sách.

| Kịch bản Đe dọa (Threat Scenario) | Nguy cơ | Biện pháp Phòng thủ Thiết kế |
| :--- | :--- | :--- |
| **Tài khoản Telegram của Admin bị đánh cắp** | Kẻ tấn công gửi lệnh điều khiển máy chủ thông qua phiên chat Telegram hợp lệ. | Bắt buộc xác thực **TOTP 2FA (RFC 6238)** được sinh offline trên máy chủ. Khóa tài khoản sau 5 lần nhập sai với exponential backoff. Session lưu thuần RAM và hết hạn sau 10 phút không hoạt động (idle) hoặc tối đa 1 giờ. |
| **Telegram Bot Token bị rò rỉ** | Kẻ tấn công gọi Telegram Bot API trực tiếp hoặc giả lập bot. | Token chỉ dùng để giao tiếp outbound HTTPS kéo cập nhật từ Telegram. Máy chủ không mở port inbound nào. Mã lệnh chỉ thực thi khi có TOTP hợp lệ của Telegram User ID nằm trong allowlist máy chủ. Bot discard pending updates khi khởi động. |
| **Kẻ lạ (Unknown User) gửi tin nhắn cho Bot** | Kẻ lạ cố gắng spam, dò quét lệnh hoặc khai thác lỗ hổng parser. | **Im lặng tuyệt đối (Silent Drop)**. Không gửi lại bất kỳ phản hồi nào để tránh tiết lộ sự tồn tại của bot. Ghi nhận nhật ký kiểm toán với bộ lọc rate-limit chống tấn công làm tràn đĩa (log exhaustion). |
| **Tấn công Replay / Tin nhắn cũ gửi lại** | Kẻ tấn công hoặc mạng truyền tải gửi lại tin nhắn lệnh cũ khi bot vừa online trở lại. | Bỏ qua tin nhắn chờ (`drop_pending_updates=True`) khi khởi động. Từ chối mọi tin nhắn có timestamp cũ hơn 60 giây hoặc lệnh callback query đã qua sử dụng (one-time nonce). |
| **Thao túng nội dung qua Forward / Edit / Channel** | Kẻ tấn công lừa bot thực thi nội dung trích dẫn hoặc sửa tin nhắn sau khi gửi. | Bộ lọc từ chối tuyệt đối mọi tin nhắn bị chỉnh sửa (`edited_message`), tin nhắn chuyển tiếp (`forwarded`), tin nhắn từ Group / Channel / Inline Query. Chỉ chấp nhận tin nhắn văn bản thuần túy trong Private Chat. |
| **Khai thác chèn lệnh (Command Injection)** | Kẻ tấn công chèn ký tự `; && | $(...)` để thoát khỏi lệnh được cấp phép. | Chế độ mặc định `restricted` chạy trực tiếp qua vector tham số `asyncio.create_subprocess_exec` mà **không thông qua shell**, triệt tiêu hoàn toàn khả năng chèn ký tự đặc biệt của shell. Tham số được kiểm tra nghiêm ngặt bằng regex hoặc enum. |
| **Leo thang đặc quyền (Privilege Escalation)** | Tiến trình bot bị chiếm quyền điều khiển và tìm cách chiếm quyền root. | Bot tuyệt đối từ chối khởi động dưới quyền `root`. Chạy dưới tài khoản hệ thống chuyên biệt `telegram-bot` không có login shell. Sandbox systemd cô lập filesystem (`ProtectSystem=strict`, `ProtectHome=yes`, `CapabilityBoundingSet=` rỗng, `PrivateTmp=yes`). Lệnh Sudo bị giới hạn bằng cấu hình exact-match trong `sudoers.d`, không dùng wildcard. |
| **Rò rỉ bí mật qua kênh chat Telegram** | Đầu ra lệnh in token, khóa SSH, mật khẩu cơ sở dữ liệu lên Telegram Cloud (không mã hóa E2E). | Toàn bộ đầu ra được làm sạch qua bộ lọc `redact_secrets`: tự động phát hiện và che giấu Bot Token, RSA/EC Private Keys, AWS Access Keys, cấu trúc `key=password` và mã OTP trước khi phát ra màn hình. |

---

## 2. Bản đồ 19 Yêu cầu Bảo mật (Security Requirements Verification)

| STT | Yêu cầu Thiết kế | Cách thức Hiện thực & Kiểm chứng |
| :---: | :--- | :--- |
| **1** | Xác thực bằng Allowlist User ID số nguyên (Numeric ID); cấm username; dừng khởi động nếu danh sách rỗng. | Kiểm chứng trong `src/config.py` và `src/identity.py`. Unit tests: `test_config.py`, `test_identity.py`. |
| **2** | Chỉ xử lý tin nhắn text trong Private Chat (`chat.id == user.id`) và callback query; bỏ qua edited, forwarded, groups, channels, inline. | Hiện thực trong `IdentityFilter.validate_update()`. Unit tests: `test_identity.py`. |
| **3** | Xóa cập nhật chờ khi khởi động (`drop_pending_updates=True`); bỏ qua tin nhắn cũ quá 60s. | Khởi động bot với `drop_pending_updates=True`; kiểm tra `age > 60.0` trong `IdentityFilter`. |
| **4** | Người gửi không có trong allowlist bị drop im lặng; ghi log kiểm toán có rate limit chống flood đĩa. | Phương thức `_should_audit_unknown_sender()` với cửa sổ 60s; không phản hồi tin nhắn lạ. |
| **5** | Bắt buộc TOTP 2FA (RFC 6238); sinh offline; độ lệch tối đa 1 bước (30s); chống replay OTP; khóa sau 5 lần sai; xóa tin nhắn OTP. | `TOTPManager` trong `src/auth/totp.py`. Lệnh `message.delete()` xóa ngay lập tức tin nhắn chứa OTP trên Telegram. |
| **6** | Session lưu thuần bộ nhớ RAM; hết hạn khi idle 10 phút; hết hạn tuyệt đối 1 giờ; hủy khi `/logout` hoặc restart. | `SessionManager` trong `src/auth/session.py`. Không lưu trạng thái đăng nhập vào đĩa/cơ sở dữ liệu. |
| **7** | Xác nhận lệnh nguy hiểm ràng buộc hash nội dung (SHA-256), user_id, chat_id, message_id, nonce một lần, hết hạn 30s. | `ConfirmationManager` trong `src/auth/confirmation.py`. Callback handler kiểm tra toàn vẹn trước khi kích hoạt. |
| **8** | Từ chối chạy dưới quyền `root`; chạy dưới system user riêng biệt; sudo chỉ qua cấu hình exact-match trong `sudoers.d`. | Hàm `ensure_not_root()` trong `src/config.py`. Mẫu cấu hình `deploy/sudoers.d/telegram-bot`. |
| **9** | Hai chế độ: `restricted` (mặc định, argv vector không qua shell, enum/regex) và `shell` (tắt mặc định, bật có chủ đích). | `PolicyEngine` trong `src/policy.py`. Khởi tạo `create_subprocess_exec` độc lập không qua shell. |
| **10** | Danh sách mẫu lệnh nguy hiểm chỉ là cảnh báo giảm tốc (speed bump); ranh giới thực sự là sandbox, sudoers, user không đặc quyền. | Được ghi rõ trong tài liệu này và cấu hình mẫu regex trong `policy.yaml`. |
| **11** | Cô lập process group riêng (`setpgid`); timeout SIGTERM -> SIGKILL; stdin từ `/dev/null`; env được lọc sạch; giới hạn tài nguyên. | Hiện thực trong `ProcessExecutor` (`src/executor/process.py`) và lõi C native (`server_executor.c`). |
| **12** | Giới hạn 2 jobs đồng thời toàn cục; rate limit 10 lệnh/phút/user; lệnh `/jobs` và `/kill`. | `JobManager` trong `src/executor/jobs.py` sử dụng hàng đợi trượt và tracking PID/job ID. |
| **13** | Nạp token theo thứ tự ưu tiên: systemd creds -> file 0600 -> env; cấm ghi token/secret vào log. | `resolve_bot_token()` trong `src/config.py`; kiểm tra quyền file 0600/0400 trên Linux. |
| **14** | Làm sạch ANSI escape, che giấu bí mật (token, key, password), escape HTML pre-wrap; cắt phân trang mượt mà. | `sanitize_output()` trong `src/redaction.py` và `paginate_output()` trong `src/executor/terminals.py`. |
| **15** | Nhật ký kiểm toán JSON Lines append-only; thông báo Telegram cho admin khi có sự kiện an ninh khẩn cấp. | `AuditLogger` trong `src/audit.py`. Ghi đồng thời ra file và `sys.stdout` (journald). |
| **16** | Systemd unit với đầy đủ cờ bảo vệ: `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, rlimits, credentials. | Tệp cấu hình dịch vụ `deploy/systemd/telegram-server-bot.service`. |
| **17** | Phân quyền tương tác Sudo: hỗ trợ hỏi ý kiến người dùng (`ask`) với nút bấm inline hoặc thực thi tự động (`auto`). | Cấu hình `sudo.policy` trong `config.yaml` và bộ xử lý callback query `sudo_accept`/`sudo_reject`. |
| **18** | Gateway đa terminal (1-10 terminals) với tiền tố điều khiển dấu chấm (`.stop`, `.new`, `.t1..10`, `.close`, `.terminals`). | `TerminalGateway` trong `src/executor/terminals.py` và `dot_command_dispatcher` trong `src/handlers/system.py`. |
| **19** | Hỗ trợ phân trang khi output dài, cho phép gửi các tin nhắn nối tiếp từ vị trí dừng và ngắt tức thì qua `.stop`. | Hàm `paginate_output()` chia nhỏ khối 3500 ký tự và kiểm tra cờ `stop_requested` trước mỗi lần gửi tin. |

---

## 3. Ranh giới Bảo mật Thực sự (Real Security Boundaries)

> [!WARNING]
> **Bộ lọc nhận diện mẫu lệnh nguy hiểm (Dangerous-Pattern Regex) CHỈ LÀ GỜ GIẢM TỐC (SPEED BUMP)!**
> Bất kỳ danh sách đen regex nào cũng có thể bị qua mặt (bypass) trong môi trường shell bằng kỹ thuật xáo trộn chuỗi (string concatenation, biến môi trường, base64 decoding, v.v.).

Do đó, kiến trúc bảo mật của hệ thống **KHÔNG PHỤ THUỘC** vào bộ lọc regex để giữ an toàn cho máy chủ. Ranh giới bảo mật thực sự được thiết lập bởi 5 lớp phòng thủ độc lập:
1. **Tài khoản hệ thống không đặc quyền (`telegram-bot`)**: Không có quyền ghi vào bất kỳ thư mục hệ thống nào ngoài thư mục state/log được cấp riêng.
2. **Systemd Security Sandbox**: File system bị khóa ở chế độ chỉ đọc (`ProtectSystem=strict`), `/home` bị ẩn hoàn toàn (`ProtectHome=yes`), toàn bộ Linux Capabilities bị xóa sạch.
3. **Cấu hình Sudoers Exact-Match**: Chỉ cho phép thực thi chính xác đường dẫn tệp nhị phân được cấu hình trước trong `/etc/sudoers.d/telegram-bot`, tuyệt đối không có `ALL` và không có wildcard `*`.
4. **Xác thực Hai Bước TOTP Offline**: Ngăn chặn hoàn toàn việc chiếm quyền điều khiển ngay cả khi phiên Telegram của người dùng bị lộ.
5. **Nhật ký Kiểm toán Bất biến (Immutable Audit Trail)**: Mọi thao tác, dù thành công hay bị từ chối, đều được ghi vết tức thời vào journald của hệ điều hành.

---

## 4. Kế hoạch Ứng phó Sự cố & Xoay vòng Token (Incident Response & Token Rotation)

Nếu bạn nghi ngờ token bot hoặc khóa TOTP bị xâm nhập:

### Bước 1: Thu hồi Token trên Telegram
1. Mở ứng dụng Telegram, chat với **@BotFather**.
2. Nhập lệnh `/revoke` và chọn bot của bạn. BotFather sẽ vô hiệu hóa token cũ ngay lập tức và tạo token mới.
3. Việc này ngắt hoàn toàn kết nối của bất kỳ kẻ tấn công nào đang sử dụng token cũ.

### Bước 2: Cập nhật Token mới trên Máy chủ
- Nếu dùng Systemd Credential:
  ```bash
  echo -n "<NEW_TOKEN>" | sudo tee /etc/telegram-server-bot/bot_token
  sudo chmod 0440 /etc/telegram-server-bot/bot_token
  ```
- Khởi động lại dịch vụ:
  ```bash
  sudo systemctl restart telegram-server-bot.service
  ```

### Bước 3: Đổi khóa TOTP 2FA cho Quản trị viên
Nếu nghi ngờ bí mật TOTP bị lộ:
```bash
sudo python scripts/setup_totp.py <USER_ID>
```
Xóa phiên đăng nhập hiện tại bằng cách khởi động lại dịch vụ hoặc người dùng gửi lệnh `/logout`.

### Bước 4: Điều tra Nhật ký Kiểm toán
Kiểm tra toàn bộ lệnh đã thực thi trong khung giờ nghi vấn:
```bash
journalctl -u telegram-server-bot.service --since "2 hours ago" | grep AUDIT
```

---

## 5. Rủi ro Tồn dư (Residual Risks)

- **Telegram Cloud Privacy**: Nội dung tin nhắn chat giữa người dùng và Bot trên Telegram không được mã hóa đầu cuối (E2E Encrypted). Mặc dù bot đã lọc bỏ các bí mật phổ biến bằng regex, quản trị viên không nên hiển thị trực tiếp các tệp nhạy cảm (như private database dump, SSL private keys chưa mã hóa) ra màn hình Telegram.
- **Tùy chọn `NoNewPrivileges=no` khi bật Sudo**: Khi bạn chuyển `NoNewPrivileges=no` để sử dụng lệnh sudo, ranh giới giữa tài khoản `telegram-bot` và `root` dựa hoàn toàn vào tính chặt chẽ của tệp `/etc/sudoers.d/telegram-bot`. Hãy chắc chắn rằng các chương trình được liệt kê trong sudoers không có tính năng shell escape (ví dụ không cấp sudo cho `less`, `more`, `vi`, `find` có flag `-exec`).
