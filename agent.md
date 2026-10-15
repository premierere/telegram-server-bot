# HỒ SƠ BÀN GIAO KỸ THUẬT & HƯỚNG DẪN MÔI TRƯỜNG (`agent.md`)
## Dự án: Telegram Linux Server Administration Bot

Tài liệu này được biên soạn đầy đủ để làm hồ sơ chuyển giao (handoff / context transfer) khi đưa dự án sang một máy chủ mới hoặc tiếp tục phát triển trên một AI Agent / IDE khác mà không bị gián đoạn hay mất ngữ cảnh.

---

## 1. Thông Tin Chung & Kiến Trúc Dự Án

- **Tên dự án**: `telegram-server-bot`
- **Mục tiêu**: Quản trị máy chủ Linux từ xa qua Telegram Bot với tôn chỉ **Security-First, Defense-in-Depth, Zero-Storage**.
- **Ngôn ngữ & Nền tảng**:
  - Python 3.12+ (Asyncio, `python-telegram-bot` v21.x)
  - C Native Core (`src/native/server_executor.c`) biên dịch GCC/Clang `-O3`
  - Linux Kernel PTY (`pty.fork`, `openpty`, `/dev/tty`, `termios`)
- **Kho lưu trữ GitHub**: `https://github.com/premierere/telegram-server-bot.git` (Nhánh: `main`)

---

## 2. Cấu Trúc Mã Nguồn Hoàn Chỉnh

```text
telegram-server-bot/
├── config.example.yaml          # Tệp cấu hình mẫu (chứa ID admin, timeouts, policy)
├── policy.yaml                  # Danh mục lệnh cho chế độ restricted mode
├── pyproject.toml               # Khai báo dependency, cấu hình pytest, ruff, bandit
├── README.md                    # Tài liệu hướng dẫn sử dụng tiếng Việt
├── agent.md                     # Tài liệu bàn giao bối cảnh cho Agent/Máy mới
├── bin/
│   └── server_executor          # Nhị phân C native sau khi biên dịch
├── deploy/
│   ├── CREDENTIALS.md           # Hướng dẫn nạp bot token qua Systemd Credentials
│   ├── sudoers.d/
│   │   └── telegram-bot         # Phân quyền sudo tối thiểu (không wildcard, không ALL)
│   └── systemd/
│       └── telegram-server-bot.service  # Đơn vị dịch vụ systemd (đã tối ưu sandbox cho su/sudo)
├── docs/
│   ├── PROGRESS.md              # Lịch sử hoàn thành các Milestone 1 -> 12
│   └── SECURITY.md              # Báo cáo mô hình đe dọa và 19 yêu cầu an ninh
├── scripts/
│   └── setup_totp.py            # Script sinh mã bí mật TOTP 2FA cho admin
├── src/
│   ├── __init__.py
│   ├── audit.py                 # Ghi nhật ký kiểm toán JSONL và cảnh báo admin
│   ├── bot.py                   # Lớp BotApplication, kết nối middleware, đăng ký handlers
│   ├── config.py                # Schema validation, kiểm tra root, kiểm tra quyền file 0600
│   ├── identity.py              # Gatekeeper lọc User ID, private chat, chống replay tin nhắn >60s
│   ├── main.py                  # Điểm khởi chạy CLI chính
│   ├── messages.py              # Toàn bộ câu thoại bản địa hóa tiếng Việt
│   ├── policy.py                # Policy Engine: phân tích cú pháp argv, phát hiện lệnh nguy hiểm
│   ├── redaction.py             # Lọc mã màu ANSI escape, che giấu secrets/tokens/keys
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── confirmation.py      # Quản lý xác nhận lệnh nguy hiểm / Sudo qua inline buttons
│   │   ├── pam_verifier.py      # Xác thực Linux 5 tầng không lưu mật khẩu (Zero-Storage)
│   │   ├── session.py           # Quản lý phiên RAM (idle timeout 10m, absolute 1h)
│   │   ├── state.py             # State machine (TOTP -> User -> Pass), retry 5 lần, logout/exit
│   │   └── totp.py              # Xác thực 2FA TOTP (RFC 6238), drift 1 bước, lockout 5 lần
│   ├── executor/
│   │   ├── __init__.py
│   │   ├── jobs.py              # Giới hạn đồng thời (max 2), rate limit (10/phút), /jobs, /kill
│   │   ├── native_bridge.py     # Cầu nối giữa Python và lõi C native (fallback ProcessExecutor)
│   │   ├── process.py           # Quản lý tiến trình độc lập, PGID, DEVNULL stdin, stream cap 1MB
│   │   ├── pty_session.py       # Quản lý 10 Virtual Terminal PTY, trích xuất prompt máy chủ thực
│   │   └── terminals.py         # Terminal Gateway và phân trang đầu ra tin nhắn
│   ├── handlers/
│   │   ├── __init__.py
│   │   ├── auth.py              # /login, /logout, /exit handlers
│   │   ├── command.py           # direct_text_dispatcher, /run, confirmation callbacks
│   │   ├── error.py             # Bắt lỗi toàn cục và cảnh báo quản trị viên
│   │   └── system.py            # /status, /whoami, /jobs, /kill, /help, /stop, /new, /t1..10, /terminals, /close
│   └── native/
│       └── server_executor.c    # Lõi thực thi C: fork, setsid, pipe, sanitize env, rlimits
└── tests/                       # Toàn bộ 84 unit & integration tests (100% Passed)
```

---

## 3. Quy Trình Xác Thực & Trải Nghiệm Người Dùng (UX Flow)

1. **Bước 1 (TOTP 2FA)**:
   - Gõ `/login <MÃ_OTP>` (Ví dụ: `/login 123456`).
   - Tin nhắn chứa mã OTP bị xóa tự động lập tức để bảo vệ màn hình.
   - Sai quá 5 lần sẽ bị khóa tạm thời 5 phút (backoff).
2. **Bước 2 (Chọn Tài Khoản Linux)**:
   - Nhập tên user muốn làm việc (ví dụ: `ubuntu`, `guest`, `root`).
3. **Bước 3 (Nhập Mật Khẩu Linux - Zero Storage)**:
   - Nhập mật khẩu. Tin nhắn chứa mật khẩu được xóa ngay lập tức.
   - Mật khẩu được chuyển thẳng qua kernel pipe/ctypes để xác thực và **không lưu lại bất cứ đâu**.
   - Nếu sai < 5 lần: Cho phép nhập lại.
   - Nếu sai 5 lần: Tự động đưa về Bước 2 yêu cầu nhập lại tên tài khoản.
4. **Bước 4 (Thực thi Dòng Lệnh Không Cần `/run`)**:
   - Gõ trực tiếp câu lệnh shell (`ls -la`, `docker ps`, `df -h`).
   - Đầu ra kèm theo banner chuẩn phản ánh đúng trạng thái thực tế:
     ```text
     Terminal1 - 15/10/2026 00:45:10
     ubuntu@server:~$
     ```
5. **Bước 5 (Điều khiển Đa Terminal)**:
   - `/new`: Mở terminal mới cùng tài khoản hiện tại.
   - `/new <user>`: Mở terminal dưới quyền user khác (yêu cầu nhập mật khẩu của user đó).
   - `/t1` .. `/t10`: Chuyển đổi qua lại giữa các terminal.
   - `/terminals`: Liệt kê danh sách terminal.
   - `/stop`: Gửi tín hiệu ngắt (Ctrl+C / SIGINT) tiến trình đang chạy.
   - `/logout`: Đóng các terminal, giữ nguyên TOTP, quay về bước chọn tài khoản.
   - `/exit`: Hủy phiên hoàn toàn, muốn dùng lại phải `/login` từ đầu.

---

## 4. Cơ Chế Xác Thực Linux PAM 5 Tầng (`src/auth/pam_verifier.py`)

Hệ thống kết hợp 5 cơ chế phân tầng linh hoạt nhằm khắc phục triệt để lỗi từ chối mật khẩu:
- **Tầng 1 (Direct Shadow)**: Nếu tiến trình có quyền đọc `/etc/shadow`, sử dụng `crypt` / `libcrypt.so.1` xác thực hàm băm SHA-512 / yescrypt tức thì trong RAM.
- **Tầng 2 (PTY Fork Interactive `su`)**:
  - Dùng `pty.fork()` thiết lập session leader.
  - Gọi `fcntl.ioctl(0, termios.TIOCSCTTY, 0)` gắn slave PTY làm controlling terminal.
  - Chạy `[su_binary, "-c", "exit 0", username]` (tùy chọn `-c` bắt buộc đứng trước `username` để không làm treo interactive shell; không truyền `-s` để tương thích shadow-utils).
  - Lắng nghe prompt `:` từ PTY trước khi đẩy mật khẩu kèm `\n`.
  - Hỗ trợ tự động thử nghiệm phiên bản `password.strip()` nếu bản gốc thất bại (chống lỗi bàn phím ảo điện thoại tự thêm dấu cách).
- **Tầng 3 (PTY Openpty Fallback)**: Dự phòng khi môi trường hạn chế fork trực tiếp.
- **Tầng 4 (In-process ctypes `libpam.so`)**: Gọi trực tiếp C bindings PAM qua các dịch vụ (`su`, `login`, `common-auth`).
- **Tầng 5 (Sudo Stdin)**: Hỗ trợ xác thực tài khoản `root` trên Ubuntu/Debian (khi root bị khóa mật khẩu `!` trong shadow, xác thực quyền root bằng mật khẩu sudo của quản trị viên).

---

## 5. Hướng Dẫn Triển Khai Sang Máy Mới (Deployment Guide)

### Bước 1: Chuẩn bị máy chủ Linux (Ubuntu 22.04 / 24.04 hoặc Debian 12)
```bash
# Cài đặt các gói phụ thuộc
sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip gcc make git

# Tạo người dùng hệ thống chuyên biệt
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/telegram-server-bot -m telegram-bot
sudo mkdir -p /etc/telegram-server-bot /var/log/telegram-server-bot /var/lib/telegram-server-bot/totp
sudo chown -R telegram-bot:telegram-bot /var/lib/telegram-server-bot /var/log/telegram-server-bot
```

### Bước 2: Tải mã nguồn & Cài đặt môi trường ảo
```bash
cd /opt
sudo git clone https://github.com/premierere/telegram-server-bot.git
cd /opt/telegram-server-bot
sudo chown -R telegram-bot:telegram-bot /opt/telegram-server-bot

sudo -u telegram-bot python3 -m venv venv
sudo -u telegram-bot ./venv/bin/pip install -U pip setuptools wheel
sudo -u telegram-bot ./venv/bin/pip install -e .
```

### Bước 3: Biên dịch Lõi Thực thi C
```bash
sudo mkdir -p bin
sudo gcc -O3 src/native/server_executor.c -o bin/server_executor
sudo chown root:telegram-bot bin/server_executor
sudo chmod 0750 bin/server_executor
```

### Bước 4: Tạo TOTP 2FA cho ID Telegram của bạn
```bash
# Lấy Telegram User ID qua bot @userinfobot trên Telegram
sudo -u telegram-bot ./venv/bin/python scripts/setup_totp.py <YOUR_TELEGRAM_USER_ID>
# Quét mã QR hoặc nhập chuỗi secret vào Google Authenticator / Bitwarden
```

### Bước 5: Cấu hình bot & Token
```bash
sudo cp config.example.yaml /etc/telegram-server-bot/config.yaml
sudo cp policy.yaml /etc/telegram-server-bot/policy.yaml

# Cập nhật allowed_user_ids và admin_user_ids trong config.yaml
sudo nano /etc/telegram-server-bot/config.yaml

# Thiết lập Bot Token
echo -n "YOUR_BOT_TOKEN_HERE" | sudo tee /etc/telegram-server-bot/bot_token
sudo chown root:telegram-bot /etc/telegram-server-bot/config.yaml /etc/telegram-server-bot/policy.yaml /etc/telegram-server-bot/bot_token
sudo chmod 0640 /etc/telegram-server-bot/config.yaml /etc/telegram-server-bot/policy.yaml
sudo chmod 0440 /etc/telegram-server-bot/bot_token
```

### Bước 6: Phân quyền Sudo (Tùy chọn) & Kích hoạt Systemd
```bash
# Phân quyền sudoers tối thiểu
sudo cp deploy/sudoers.d/telegram-bot /etc/sudoers.d/telegram-bot
sudo chmod 0440 /etc/sudoers.d/telegram-bot

# Kích hoạt systemd service
sudo cp deploy/systemd/telegram-server-bot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now telegram-server-bot.service
sudo systemctl status telegram-server-bot.service
```

---

## 6. Kiểm Thử & Tiêu Chuẩn Chất Lượng (Quality Gates)

Mọi thay đổi trên mã nguồn đều phải đảm bảo vượt qua 3 cổng kiểm tra sau:
1. **Pytest (Unit & Integration)**:
   ```bash
   pytest -v  # Đạt 84/84 tests pass (100%)
   ```
2. **Linter (Ruff)**:
   ```bash
   ruff check .  # Đạt 0 lỗi
   ```
3. **Security Audit (Bandit)**:
   ```bash
   bandit -c pyproject.toml -r src/  # Đạt 0 lỗ hổng an ninh
   ```
