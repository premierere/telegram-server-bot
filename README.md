# Telegram Linux Server Administration Bot

Công cụ quản trị máy chủ Linux an toàn qua Telegram Bot, được thiết kế theo tư duy bảo mật hàng đầu (**Security-First, Defense-in-Depth, Fail-Closed**). Hệ thống giúp quản trị viên kiểm soát và vận hành máy chủ từ xa trong các điều kiện thù địch nhất (tài khoản Telegram bị xâm nhập, lộ bot token, thông điệp giả mạo hoặc lỗi thao tác của người vận hành).

---

## 🌟 Điểm nổi bật & Tính năng chính

- **Kiến trúc Hybrid Tối ưu Tốc độ & Bảo mật**:
  - **Lớp mạng & Giao diện (Python 3.12+ Asyncio)**: Tích hợp `python-telegram-bot` v21.x chạy chế độ **Long Polling** thuần outbound HTTPS (máy chủ không cần mở bất kỳ cổng mạng inbound nào).
  - **Lõi thực thi tiến trình (Native C Core - `server_executor.c`)**: Tối ưu tốc độ thực thi, quản lý luồng dữ liệu (streaming pipe), cô lập process group và dọn dẹp biến môi trường độc lập.
- **Xác thực Đa yếu tố Bắt buộc (Mandatory 2FA)**:
  - Sinh mã bí mật TOTP (RFC 6238) hoàn toàn offline trên máy chủ qua `scripts/setup_totp.py`.
  - Tự động xóa tin nhắn chứa mã OTP trên Telegram ngay khi nhận được.
  - Chống replay mã OTP cũ và tự động khóa tài khoản sau 5 lần nhập sai với cơ chế exponential backoff.
- **Ủy quyền Định danh Chặt chẽ**:
  - Chỉ cho phép các Numeric Telegram User ID được định nghĩa trong cấu hình máy chủ.
  - Từ chối phản hồi người lạ hoàn toàn (**Silent Drop**) và ghi nhật ký có kiểm soát tốc độ để tránh làm tràn đĩa.
  - Chống tấn công Replay tin nhắn bằng cách từ chối tin nhắn cũ hơn 60 giây và xóa tin nhắn chờ (`drop_pending_updates=True`) khi khởi động.
- **Hai Chế độ Thực thi Linh hoạt & An toàn**:
  - **Restricted Mode (Mặc định)**: Thực thi theo vector tham số (`argv`) không qua shell thông qua `policy.yaml`. Kiểm tra nghiêm ngặt kiểu dữ liệu bằng regex hoặc enum, triệt tiêu mọi nguy cơ chèn lệnh (Command Injection).
  - **Shell Mode**: Cho phép chạy bash shell unprivileged đối với người dùng được cấp phép, có kèm bộ lọc cảnh báo lệnh nguy hiểm (rm, dd, mkfs, reboot, v.v.) yêu cầu xác nhận tương tác.
- **Cấp quyền Sudo Tương tác (Interactive Sudo Elevation)**:
  - Hỗ trợ cấu hình `ask`: Khi tiến trình cần quyền root, bot gửi thông điệp xác nhận kèm nút bấm inline `[Cấp quyền Sudo]` / `[Từ chối]` (hiệu lực 30 giây, ràng buộc mã nonce duy nhất chống giả mạo).
- **Gateway Đa Terminal (1 - 10 Terminals) & Bộ điều khiển Tiền tố Dấu chấm (`.`)**:
  - Hỗ trợ mở tối đa 10 terminal ảo song song.
  - Sử dụng các lệnh điều khiển nhanh: `.stop` (dừng tức thì luồng xuất dữ liệu tương tự Ctrl+C), `.new` (mở terminal mới), `.t1`..`.t10` (chuyển đổi giữa các terminal), `.terminals` (xem danh sách terminal).
- **Phân trang Đầu ra & Làm sạch Dữ liệu**:
  - Tự động lọc bỏ mã màu ANSI escape.
  - Che giấu tự động các dữ liệu nhạy cảm (Bot token, SSH/RSA Private Keys, mật khẩu, AWS access keys).
  - Phân trang đầu ra thông minh nối tiếp nhau khi dữ liệu vượt quá 3500 ký tự.
- **Cứng hóa Môi trường Triển khai (Systemd Hardening)**:
  - Từ chối khởi động dưới quyền `root`.
  - Sandbox systemd nghiêm ngặt: `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, giới hạn bộ nhớ 512MB và tối đa 64 tiến trình con.
  - Nạp token an toàn qua **Systemd Credentials** (`$CREDENTIALS_DIRECTORY/bot_token`).

---

## 📋 Yêu cầu Hệ thống

- **Hệ điều hành**: Linux (Ubuntu 22.04 / 24.04 LTS hoặc Debian 12 khuyến nghị).
- **Python**: Phiên bản 3.11 trở lên.
- **Trình biên dịch C/C++**: `gcc` hoặc `clang` (hoặc `zig cc`).

---

## 🚀 Hướng dẫn Cài đặt & Triển khai

### 1. Tạo tài khoản hệ thống chuyên biệt

Chạy dưới quyền root/sudo trên server:
```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/telegram-server-bot -m telegram-bot
sudo mkdir -p /etc/telegram-server-bot /var/log/telegram-server-bot /var/lib/telegram-server-bot/totp
sudo chown -R telegram-bot:telegram-bot /var/lib/telegram-server-bot /var/log/telegram-server-bot
```

### 2. Tải mã nguồn và Cài đặt Thư viện

```bash
cd /opt
sudo git clone https://github.com/your-org/telegram-server-bot.git
cd /opt/telegram-server-bot
sudo chown -R telegram-bot:telegram-bot /opt/telegram-server-bot

# Tạo môi trường ảo Python
sudo -u telegram-bot python3 -m venv venv
sudo -u telegram-bot ./venv/bin/pip install -U pip setuptools wheel
sudo -u telegram-bot ./venv/bin/pip install -e .
```

### 3. Biên dịch Lõi Thực thi C Native

```bash
sudo mkdir -p bin
sudo gcc -O3 src/native/server_executor.c -o bin/server_executor
sudo chown root:telegram-bot bin/server_executor
sudo chmod 0750 bin/server_executor
```

### 4. Thiết lập Mã bí mật TOTP 2FA cho Quản trị viên

Chạy script khởi tạo bí mật TOTP offline cho User ID Telegram của bạn (lấy ID qua bot `@userinfobot` trên Telegram):
```bash
sudo -u telegram-bot ./venv/bin/python scripts/setup_totp.py <YOUR_TELEGRAM_USER_ID>
```
*Nhập mã bí mật hoặc quét mã QR/URI hiển thị vào ứng dụng Google Authenticator, Bitwarden hoặc 1Password.*

### 5. Cấu hình Dịch vụ & Phân quyền Sudo

Sao chép cấu hình mẫu và cập nhật:
```bash
sudo cp config.example.yaml /etc/telegram-server-bot/config.yaml
sudo cp policy.yaml /etc/telegram-server-bot/policy.yaml
sudo chown root:telegram-bot /etc/telegram-server-bot/config.yaml /etc/telegram-server-bot/policy.yaml
sudo chmod 0640 /etc/telegram-server-bot/config.yaml /etc/telegram-server-bot/policy.yaml
```

Thiết lập Bot Token qua Systemd Credential (xem chi tiết tại [`deploy/CREDENTIALS.md`](deploy/CREDENTIALS.md)):
```bash
echo -n "YOUR_BOT_TOKEN_HERE" | sudo tee /etc/telegram-server-bot/bot_token
sudo chown root:telegram-bot /etc/telegram-server-bot/bot_token
sudo chmod 0440 /etc/telegram-server-bot/bot_token
```

Cấu hình phân quyền Sudo tối thiểu (tùy chọn):
```bash
sudo cp deploy/sudoers.d/telegram-bot /etc/sudoers.d/telegram-bot
sudo chmod 0440 /etc/sudoers.d/telegram-bot
```

### 6. Cài đặt và Kích hoạt Dịch vụ Systemd

```bash
sudo cp deploy/systemd/telegram-server-bot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now telegram-server-bot.service
sudo systemctl status telegram-server-bot.service
```

---

## 📖 Hướng dẫn Sử dụng Bot

Mở cuộc trò chuyện riêng (**Private Chat**) với Bot của bạn trên Telegram:

### 1. Đăng nhập & Xác thực
```text
/login <MÃ_6_CHỮ_SỐ_TỪ_AUTHENTICATOR>
```
*Ví dụ: `/login 123456`. Tin nhắn chứa OTP sẽ được xóa ngay lập tức để bảo vệ phiên.*

### 2. Thực thi Lệnh (`/run`)

- **Chế độ Restricted (Mặc định)**:
  ```text
  /run uptime
  /run service_status nginx.service
  ```
- **Chế độ Shell (Nếu tài khoản được bật quyền)**:
  ```text
  /run df -h
  /run free -m
  /run docker ps
  ```

### 3. Hộp thoại Xác nhận Lệnh Nguy hiểm & Sudo
- Nếu bạn nhập lệnh nguy hiểm (ví dụ `rm -rf`, `reboot`, `iptables -F`), bot sẽ hiển thị thông báo cảnh báo màu đỏ kèm 2 nút bấm: `[Xác nhận Thực thi]` và `[Hủy bỏ]`.
- Nếu lệnh yêu cầu quyền Sudo và chế độ `sudo.policy` là `ask`, bot sẽ hiển thị `[Cấp quyền Sudo]` / `[Từ chối]`. Nút bấm có hiệu lực trong 30 giây.

### 4. Điều khiển Gateway Đa Terminal (Prefix dấu chấm `.`)
- `.new` hoặc `.n`: Tạo một terminal ảo mới (tối đa 10 terminal).
- `.t1`, `.t2`, ... `.t10`: Chuyển đổi giữa các terminal đang mở.
- `.terminals`: Hiển thị danh sách terminal và thư mục làm việc hiện tại.
- `.stop`: Dừng ngay lập tức tiến trình đang chạy và ngừng phân trang output (tương tự nhấn `Ctrl + C`).
- `.close`: Đóng terminal hiện tại.

### 5. Quản lý Tác vụ & Trạng thái Hệ thống
- `/whoami`: Xem ID người dùng, chế độ thực thi (`RESTRICTED` hoặc `SHELL`), thời gian session còn lại.
- `/jobs`: Liệt kê các tiến trình dài hạn đang chạy trong hệ thống.
- `/kill <JOB_ID>`: Buộc dừng một tiến trình đang chạy bằng tín hiệu SIGTERM/SIGKILL.
- `/status`: Kiểm tra trạng thái máy chủ (Uptime, tải CPU, bộ nhớ RAM).
- `/logout`: Đăng xuất và hủy phiên làm việc ngay lập tức.

---

## 🧪 Kiểm thử Tự động (Testing)

Bộ kiểm thử được viết bằng `pytest` với 100% kịch bản kiểm thử độc lập, không phụ thuộc vào kết nối mạng bên ngoài:

```bash
# Chạy toàn bộ 64+ bài kiểm thử tự động
pytest -v
```

Để xem thông tin chi tiết về chính sách an ninh và ứng phó sự cố, vui lòng đọc [Chính sách Bảo mật (SECURITY.md)](docs/SECURITY.md).
