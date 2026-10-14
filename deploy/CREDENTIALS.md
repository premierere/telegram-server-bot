# Hướng dẫn Quản lý Bí mật với Systemd Credentials (Systemd Credentials Guide)

Dự án ưu tiên nạp Telegram Bot Token qua cơ chế **Systemd Credentials** (`$CREDENTIALS_DIRECTORY/bot_token`) theo chuẩn bảo mật hiện đại của Linux, giúp tách biệt hoàn toàn bí mật khỏi mã nguồn, tệp cấu hình thông thường và biến môi trường chung.

---

## 1. Cơ chế Hoạt động

Thứ tự ưu tiên nạp Bot Token được quy định nghiêm ngặt như sau:
1. **Systemd Credential**: `$CREDENTIALS_DIRECTORY/bot_token` (An toàn nhất, tự động tạo RAMfs riêng biệt cho service).
2. **File trên đĩa**: Đường dẫn cấu hình trong `config.yaml` (`bot_token_file`), chỉ cho phép quyền `0600` hoặc `0400`.
3. **Biến môi trường**: `TELEGRAM_BOT_TOKEN`.

---

## 2. Thiết lập Systemd Credential trên Ubuntu / Debian

### Cách 1: Sử dụng LoadCredential với tệp được bảo vệ (Đơn giản & Khuyến nghị)

1. Lưu token vào tệp bảo mật trên server:
   ```bash
   sudo mkdir -p /etc/telegram-server-bot
   echo -n "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ" | sudo tee /etc/telegram-server-bot/bot_token
   sudo chown root:telegram-bot /etc/telegram-server-bot/bot_token
   sudo chmod 0440 /etc/telegram-server-bot/bot_token
   ```

2. Trong tệp dịch vụ `/etc/systemd/system/telegram-server-bot.service`:
   ```ini
   LoadCredential=bot_token:/etc/telegram-server-bot/bot_token
   ```

3. Khi dịch vụ khởi chạy, systemd sẽ tự động gắn (mount) tệp này vào thư mục tạm thời của tiến trình tại `$CREDENTIALS_DIRECTORY/bot_token` với quyền chỉ đọc duy nhất cho tiến trình dịch vụ.

---

### Cách 2: Sử dụng Systemd Encrypted Credentials (`systemd-creds`)

Trên các phiên bản systemd 250+ (Ubuntu 22.04/24.04, Debian 12), bạn có thể mã hóa token bằng khóa phần cứng TPM2 hoặc khóa máy chủ:

1. Mã hóa token:
   ```bash
   echo -n "YOUR_BOT_TOKEN_HERE" | systemd-creds encrypt --name=bot_token - /etc/telegram-server-bot/bot_token.cred
   ```

2. Cấu hình trong unit:
   ```ini
   SetCredentialEncrypted=bot_token:....
   # Hoặc nạp từ file đã mã hóa:
   LoadCredentialEncrypted=bot_token:/etc/telegram-server-bot/bot_token.cred
   ```

---

## 3. Quy trình Xoay vòng Token (Token Rotation) khi nghi ngờ rò rỉ

Nếu phát hiện token bị nghi ngờ lộ hoặc sao chép trái phép:

1. Truy cập **@BotFather** trên Telegram ngay lập tức:
   - Gửi lệnh `/revoke` và chọn Bot của bạn để vô hiệu hóa token cũ tức thì.
   - Sao chép Token mới vừa được cấp.
2. Cập nhật token mới vào tệp credential trên server:
   ```bash
   echo -n "NEW_BOT_TOKEN_HERE" | sudo tee /etc/telegram-server-bot/bot_token
   ```
3. Khởi động lại dịch vụ:
   ```bash
   sudo systemctl restart telegram-server-bot.service
   ```
4. Kiểm tra nhật ký kiểm toán (Audit log) để phát hiện các lệnh bất thường trong khoảng thời gian nghi vấn:
   ```bash
   journalctl -u telegram-server-bot.service --since "1 hour ago"
   ```
