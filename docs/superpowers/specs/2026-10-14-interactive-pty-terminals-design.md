# Thiết kế Kỹ thuật: Hệ thống Điều khiển Terminal TTY Tương tác Đa Người dùng

**Ngày tạo:** 14/10/2026  
**Trạng thái:** Đã phê duyệt (Approved)

---

## 1. Mục tiêu (Goals) & Phạm vi (Scope)

Chuyển đổi bot Telegram từ mô hình thực thi đơn lệnh rời rạc (`/run <cmd>`) sang **Cổng điều khiển Terminal tương tác dòng lệnh thực tế (Line-by-line Interactive Shell Gateway)** kết nối trực tiếp với shell của máy chủ Linux:
1. **Xác thực Đa tầng không lưu mật khẩu (Zero-Storage PAM Auth)**:
   - Bước 1: `/login <TOTP_CODE>` (RFC 6238).
   - Bước 2: Nhập Tên Tài khoản Linux trên máy chủ (ví dụ `root`, `guest`, `ubuntu`).
   - Bước 3: Nhập Mật khẩu tài khoản Linux: bot xóa ngay tin nhắn chứa mật khẩu, đẩy vào Linux PAM qua PTY `su - <username>` để kiểm tra. Tuyệt đối không lưu mật khẩu vào file hay RAM lâu dài.
   - Cơ chế thử lại mật khẩu: Cho phép thử lại tối đa 5 lần nếu sai. Nếu sai quá 5 lần, chuyển người dùng quay lại bước nhập tên tài khoản.
2. **Loại bỏ Tiền tố `/run`**:
   - Mọi tin nhắn văn bản thông thường không bắt đầu bằng `/` sẽ được chuyển trực tiếp vào shell terminal đang hoạt động.
3. **Loại bỏ Tiền tố Dấu chấm (`.`) & Dồn về Slash (`/`)**:
   - `/stop`: Gửi tín hiệu ngắt `SIGINT` (Ctrl+C) ngắt tiến trình đang chạy và dừng phân trang output.
   - `/new`: Tự động mở terminal mới cho người dùng hiện tại (không cần mật khẩu).
   - `/new <user>`: Yêu cầu mật khẩu của `<user>`, xác thực qua PAM rồi mới mở terminal chạy dưới quyền `<user>`.
   - `/t1`, `/t2`... `/t10`: Chuyển đổi qua lại giữa các terminal (tối đa 10 terminal).
   - `/terminals`: Liệt kê các terminal, người dùng tương ứng và trạng thái.
   - `/close`: Đóng terminal hiện tại.
4. **Định dạng Hiển thị Terminal Prompt Trực tiếp từ PTY**:
   - Không tự định nghĩa hay hardcode prompt. Lấy trực tiếp từ dòng `PS1` cuối cùng của shell PTY:
     ```text
     Terminal<N> - <thời gian đăng nhập terminal này>
     <prompt pty>
     ```
     Ví dụ:
     ```text
     Terminal1 - 14/10/2026 16:28:09
     root@ubuntu-srv:/var/log# 
     ```
5. **Phân biệt `/logout` và `/exit`**:
   - `/logout`: Đăng xuất khỏi tài khoản Linux hiện tại, đóng các terminal tương ứng, giữ phiên xác thực TOTP và quay về bước **Nhập Tên Tài khoản**.
   - `/exit`: Thoát toàn bộ hệ thống, xóa sạch mọi phiên trong RAM, yêu cầu bắt đầu lại từ `/start` hoặc `/login <TOTP>`.

---

## 2. Kiến trúc & Máy trạng thái (State Machine)

### 2.1 Các Trạng thái Phiên của Người dùng
```
                     ┌───────────────────────────────────────────────┐
                     │                                               │
                     ▼                                               │
               [UNAUTHENTICATED]                                     │
                     │                                               │
                     │ /login <TOTP>                                 │
                     ▼                                               │
              [AWAITING_USERNAME] ◄────────────────────┐             │
                     │                                 │             │
                     │ Gửi username                    │             │
                     ▼                                 │             │
              [AWAITING_PASSWORD]                      │             │
                     │                                 │             │
        ┌────────────┴────────────┐                    │             │
        │ Sai < 5     Sai ≥ 5     │ Đúng               │             │
        ▼             ▼           ▼                    │             │
     Thử lại       Reset đếm  [AUTHENTICATED]          │             │
   (Nhập lại mk)   và quay lại     │                   │             │
                                   ├── Lệnh thường     │             │
                                   │   (gõ thẳng)      │             │
                                   ├── /new, /t1..t10  │             │
                                   ├── /stop           │             │
                                   ├── /logout ────────┘             │
                                   └── /exit ────────────────────────┘
```

### 2.2 Quản lý Đa Terminal & PTY Process
Mỗi Terminal là một thực thể `PTYTerminalSession`:
- `terminal_id`: Số thứ tự từ 1 đến 10.
- `username`: Tên user Linux đang chạy phiên (`root`, `guest`, v.v.).
- `login_time`: Thời điểm khởi tạo terminal.
- `pty_master`: File descriptor PTY master (POSIX) hoặc pipe process (Windows dev test).
- `cwd`: Thư mục làm việc hiện tại.
- `last_prompt`: Chuỗi prompt thực tế bắt được từ PTY.
- `stop_requested`: Cờ boolean báo hiệu yêu cầu ngắt.
