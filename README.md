# Telegram Linux Server Administration Bot

Công cụ quản trị máy chủ Linux an toàn qua Telegram Bot, được thiết kế theo tư duy bảo mật hàng đầu (**Security-First, Defense-in-Depth, Fail-Closed**). Hệ thống giúp quản trị viên kiểm soát và vận hành máy chủ từ xa trong các điều kiện thù địch nhất (tài khoản Telegram bị xâm nhập, lộ bot token, thông điệp giả mạo hoặc lỗi thao tác của người vận hành).

---

## 🌟 Điểm nổi bật & Tính năng chính

- **Kiến trúc Hybrid Tối ưu Tốc độ & Bảo mật**:
  - **Lớp mạng & Giao diện (Python 3.12+ Asyncio)**: Tích hợp `python-telegram-bot` v21.x chạy chế độ **Long Polling** thuần outbound HTTPS (máy chủ không cần mở bất kỳ cổng mạng inbound nào).
  - **Lõi thực thi tiến trình (Native C Core - `server_executor.c`)**: Tối ưu tốc độ thực thi, quản lý luồng dữ liệu (streaming pipe), cô lập process group và dọn dẹp biến môi trường độc lập.
- **Shell Tương tác Dòng lệnh (Line-by-Line Interactive Shell)**:
  - **Không cần tiền tố `/run`**: Mọi tin nhắn văn bản thông thường đều được chuyển thẳng vào shell terminal đang kích hoạt.
  - **Prompt biểu diễn chân thực từ PTY**: Định dạng chuẩn hóa phản ánh trạng thái tài khoản và môi trường:
    ```text
    Terminal<N> - <thời gian đăng nhập>
    <prompt pty>
    ```
- **Xác thực Đa bước & Không Lưu Trữ Mật khẩu (Zero-Storage PAM)**:
  - **Bước 1**: Nhập `/login <MÃ_OTP>` (RFC 6238). Tin nhắn OTP được xóa tự động.
  - **Bước 2**: Nhập tên tài khoản Linux trên máy chủ (ví dụ: `ubuntu`, `root`, `guest`).
  - **Bước 3**: Nhập mật khẩu Linux. Tin nhắn mật khẩu được xóa ngay lập tức trên Telegram. Mật khẩu được xác thực trực tiếp qua Linux PAM (`su`) và **hoàn toàn không bao giờ lưu trữ** trên đĩa hay trong bộ nhớ RAM (`zero persistent storage`).
  - **Khóa thử sai thông minh**: Nếu nhập sai mật khẩu < 5 lần, bot cho phép thử lại. Nếu sai liên tiếp 5 lần, tự động chuyển về bước nhập tên tài khoản Linux.
- **Gateway Đa Terminal Đa Người dùng (Multi-User Multi-Terminal Gateway)**:
  - Hỗ trợ tối đa 10 terminal ảo hoạt động song song.
  - Mỗi terminal có thể chạy dưới một tài khoản Linux độc lập (ví dụ: Terminal 1 là `ubuntu`, Terminal 2 là `guest`, Terminal 3 là `root`).
  - `/new`: Mở terminal mới cho tài khoản hiện tại mà không cần nhập lại mật khẩu.
  - `/new <tên_user>`: Yêu cầu nhập mật khẩu của user đó trước khi cấp phát terminal riêng biệt.
- **Hệ thống Lệnh Slash (`/`) Đồng nhất**:
  - Toàn bộ lệnh điều khiển gateway được dồn về tiền tố slash:
  - `/stop`: Gửi tín hiệu ngắt (Ctrl+C / SIGINT) tới tiến trình đang chạy.
  - `/new [user]`: Mở terminal mới cho user hiện tại hoặc user chỉ định.
  - `/t1` .. `/t10`: Chuyển đổi nhanh giữa các terminal.
  - `/terminals`: Liệt kê các terminal đang mở và tài khoản tương ứng.
  - `/close [ID]`: Đóng terminal.
- **Phân định Rõ ràng `/logout` và `/exit`**:
  - `/logout`: Đóng các terminal đang mở, giữ nguyên phiên xác thực TOTP, quay lại bước chọn tài khoản Linux.
  - `/exit`: Hủy toàn bộ phiên làm việc, xóa sạch trạng thái RAM, yêu cầu `/login <TOTP>` lại từ đầu.
- **Ủy quyền Định danh Chặt chẽ**:
  - Chỉ cho phép các Numeric Telegram User ID được định nghĩa trong cấu hình máy chủ.
  - Từ chối phản hồi người lạ hoàn toàn (**Silent Drop**) và ghi nhật ký có kiểm soát tốc độ để tránh làm tràn đĩa.
  - Chống tấn công Replay tin nhắn bằng cách từ chối tin nhắn cũ hơn 60 giây và xóa tin nhắn chờ (`drop_pending_updates=True`) khi khởi động.
- **Cấp quyền Sudo Tương tác (Interactive Sudo Elevation)**:
  - Hỗ trợ cấu hình `ask`: Khi tiến trình cần quyền root, bot gửi thông điệp xác nhận kèm nút bấm inline `[Cấp quyền Sudo]` / `[Từ chối]` (hiệu lực 30 giây, ràng buộc mã nonce duy nhất chống giả mạo).
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

### 1. Quy trình Đăng nhập Đa bước An toàn
1. **Bước 1**: Gõ `/login <MÃ_OTP>` (Ví dụ: `/login 123456`). Tin nhắn chứa mã OTP sẽ bị xóa ngay lập tức.
2. **Bước 2**: Nhập tên tài khoản Linux trên máy chủ (ví dụ: `ubuntu`, `guest`, `root`).
3. **Bước 3**: Nhập mật khẩu Linux của tài khoản. Tin nhắn chứa mật khẩu được xóa ngay tức thì. Sau khi xác thực PAM thành công, Terminal #1 sẽ được tự động kích hoạt.

### 2. Thực thi Dòng lệnh Trực tiếp (Không cần `/run`)
- Chỉ cần gõ trực tiếp câu lệnh vào khung chat Telegram:
  ```text
  uptime
  free -m
  df -h
  docker ps
  tail -n 20 /var/log/syslog
  ```
- Kết quả được trả về kèm biểu diễn prompt terminal thực:
  ```text
  Terminal1 - 14/10/2026 15:30:00
  ubuntu@server:~$
  ```

### 3. Quản lý Đa Terminal & Đa Tài khoản Linux
- `/new`: Mở terminal mới cho tài khoản Linux hiện tại mà không cần nhập lại mật khẩu.
- `/new <tên_user>`: Mở terminal mới dưới quyền một tài khoản Linux khác (ví dụ: `/new root`, `/new guest`). Bot sẽ yêu cầu nhập mật khẩu của tài khoản đó.
- `/t1`, `/t2`, ... `/t10`: Chuyển đổi qua lại giữa các terminal 1 đến 10.
- `/terminals`: Hiển thị danh sách các terminal đang hoạt động và tài khoản gắn liền.
- `/stop`: Gửi tín hiệu ngắt (Ctrl+C / SIGINT) để dừng lệnh đang chạy trên terminal hiện tại.
- `/close [ID]`: Đóng một terminal cụ thể hoặc terminal đang kích hoạt.

### 4. Đăng xuất & Thoát
- `/logout`: Đăng xuất khỏi tài khoản Linux, đóng các terminal, giữ lại phiên TOTP và quay lại bước nhập tên tài khoản Linux.
- `/exit`: Thoát hoàn toàn khỏi hệ thống, hủy toàn bộ phiên làm việc trên RAM, yêu cầu `/login <TOTP>` lại từ đầu.

### 5. Quản lý Tác vụ & Trạng thái Hệ thống
- `/whoami`: Xem Telegram ID, tài khoản Linux hiện tại, thời gian phiên còn lại và terminal đang chọn.
- `/jobs`: Liệt kê các tác vụ dài hạn đang chạy trong hệ thống.
- `/kill <JOB_ID>`: Buộc dừng một tiến trình đang chạy bằng tín hiệu SIGTERM/SIGKILL.
- `/status`: Kiểm tra trạng thái máy chủ (Uptime, tải CPU, bộ nhớ RAM).

---

## 🧪 Kiểm thử Tự động (Testing)

Bộ kiểm thử được viết bằng `pytest` với 100% kịch bản kiểm thử độc lập, không phụ thuộc vào kết nối mạng bên ngoài:

```bash
# Chạy toàn bộ 64+ bài kiểm thử tự động
pytest -v
```

Để xem thông tin chi tiết về chính sách an ninh và ứng phó sự cố, vui lòng đọc [Chính sách Bảo mật (SECURITY.md)](docs/SECURITY.md).
