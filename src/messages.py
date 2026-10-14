"""Centralized Vietnamese localization messages for the Telegram Administration Bot.

All user-facing bot responses, error messages, prompts, and notifications are stored here.
Code, identifiers, comments, and internal logs remain in English.
"""

from __future__ import annotations

# Authentication & Session
MSG_LOGIN_USAGE = (
    "ℹ️ <b>Hướng dẫn đăng nhập:</b>\n"
    "Cú pháp: <code>/login MÃ_OTP_6_SỐ</code>\n"
    "Ví dụ: <code>/login 123456</code>\n"
    "<i>Lưu ý: Mã OTP sinh từ ứng dụng Authenticator và chỉ có hiệu lực trong 30 giây.</i>"
)
MSG_LOGIN_SUCCESS = (
    "✅ <b>Đăng nhập thành công!</b>\n"
    "Phiên làm việc đã được kích hoạt trong bộ nhớ RAM.\n"
    "⏱️ Hết hạn chờ (Idle): 10 phút | Hết hạn tối đa (Absolute): 1 giờ.\n"
    "Gõ <code>/help</code> để xem danh sách lệnh được phép."
)
MSG_LOGIN_FAILED = "❌ <b>Mã OTP không chính xác.</b> Vui lòng thử lại."
MSG_LOGIN_ALREADY = "ℹ️ Bạn đã đăng nhập và phiên làm việc vẫn đang hoạt động."
MSG_LOGIN_CODE_USED = "⚠️ <b>Mã OTP này đã được sử dụng.</b> Vui lòng đợi mã mới."
MSG_LOGIN_LOCKED = (
    "🚨 <b>Tài khoản đã bị tạm khóa!</b>\n"
    "Bạn đã nhập sai mã xác thực quá 5 lần.\n"
    "Vui lòng thử lại sau <b>{seconds}</b> giây."
)
MSG_NOT_LOGGED_IN = (
    "🔒 <b>Yêu cầu xác thực:</b>\n"
    "Bạn chưa đăng nhập. Vui lòng dùng lệnh <code>/login MÃ_OTP</code> để bắt đầu."
)
MSG_LOGOUT_SUCCESS = "🚪 <b>Đã đăng xuất.</b> Phiên làm việc trên RAM đã được hủy an toàn."
MSG_SESSION_EXPIRED_IDLE = "⏱️ <b>Phiên làm việc đã hết hạn do không hoạt động (10 phút).</b> Vui lòng /login lại."
MSG_SESSION_EXPIRED_ABSOLUTE = "⏱️ <b>Phiên làm việc đã chạm mốc tối đa (1 giờ).</b> Vui lòng /login lại."

# Policy & Execution
MSG_RUN_USAGE = "ℹ️ <b>Cú pháp:</b> <code>/run &lt;tên_lệnh&gt; [tham_số...]</code>"
MSG_RESTRICTED_REJECTED = (
    "⛔ <b>Lệnh bị từ chối bởi chính sách an toàn (Policy Engine):</b>\n"
    "Lý do: <code>{reason}</code>\n"
    "<i>Trong chế độ restricted, mọi tham số phải khớp chính xác enum hoặc regex đã định nghĩa.</i>"
)
MSG_RATE_LIMIT_EXCEEDED = (
    "⏳ <b>Vượt quá giới hạn tần suất!</b>\n"
    "Bạn chỉ có thể thực hiện tối đa 10 lệnh mỗi phút.\n"
    "Vui lòng đợi <b>{wait_seconds}</b> giây trước khi thử lại."
)
MSG_CONCURRENCY_LIMIT_EXCEEDED = (
    "⚠️ <b>Hệ thống đang bận:</b>\n"
    "Đang có tối đa 2 tác vụ chạy đồng thời trên máy chủ.\n"
    "Vui lòng kiểm tra bằng <code>/jobs</code> hoặc đợi tác vụ hiện tại hoàn tất."
)
MSG_COMMAND_TIMEOUT = "⏱️ <b>Lệnh đã bị ngắt do vượt quá thời gian chờ (Timeout).</b>"
MSG_COMMAND_STOPPED = "🛑 <b>Tiến trình đã bị dừng lại bởi lệnh .stop (Ctrl+C).</b>"

# Dangerous Command Confirmation
MSG_DANGEROUS_CONFIRMATION_PROMPT = (
    "⚠️ <b>CẢNH BÁO LỆNH NGUY HIỂM:</b>\n\n"
    "Lệnh yêu cầu:\n<pre><code class='language-text'>{command}</code></pre>\n\n"
    "Lệnh này khớp với danh sách mẫu có thể gây hại cho hệ thống.\n"
    "Bạn có chắc chắn muốn thực thi không? (Thời hạn: 30 giây)"
)
BTN_CONFIRM_EXECUTION = "🔴 Xác nhận thực thi"
BTN_CANCEL_EXECUTION = "⚪ Hủy bỏ"
MSG_CONFIRMATION_EXPIRED = "⏱️ <b>Yêu cầu xác nhận đã hết hạn (quá 30 giây).</b> Lệnh đã bị hủy bỏ."
MSG_CONFIRMATION_CANCELLED = "⚪ <b>Đã hủy bỏ lệnh.</b>"
MSG_CONFIRMATION_INVALID = "❌ <b>Yêu cầu xác nhận không hợp lệ hoặc đã được sử dụng.</b>"

# Sudo Elevation
MSG_SUDO_CONFIRMATION_PROMPT = (
    "🛡️ <b>YÊU CẦU QUYỀN QUẢN TRỊ (SUDO):</b>\n\n"
    "Lệnh:\n<pre><code class='language-text'>{command}</code></pre>\n\n"
    "Tiến trình này yêu cầu quyền sudo. Bạn có đồng ý cấp quyền không? (Hạn: 30s)"
)
BTN_SUDO_ACCEPT = "🛡️ Cấp quyền Sudo"
BTN_SUDO_REJECT = "❌ Từ chối Sudo"
MSG_SUDO_REJECTED = "❌ <b>Đã từ chối cấp quyền sudo.</b> Lệnh không được thực thi."
MSG_SUDO_DISABLED = "⛔ <b>Chính sách máy chủ hiện đang vô hiệu hóa quyền sudo.</b>"

# Multi-terminal & Gateway
MSG_TERMINAL_SWITCHED = "📟 <b>Đã chuyển sang Terminal #{tid}</b> [Trạng thái: <code>{status}</code>]"
MSG_TERMINAL_NEW = "📟 <b>Đã mở và kích hoạt Terminal mới #{tid}.</b>"
MSG_TERMINAL_LIMIT = "⚠️ <b>Đã đạt giới hạn tối đa 10 terminals.</b> Dùng <code>.close [ID]</code> để đóng bớt."
MSG_TERMINAL_CLOSED = "🗑️ <b>Đã đóng Terminal #{tid}.</b> Terminal hiện tại: #{active_id}."
MSG_TERMINAL_STOPPED = "🛑 <b>Đã gửi tín hiệu ngắt (.stop / Ctrl+C) tới Terminal #{tid}.</b>"
MSG_TERMINAL_LIST_HEADER = "📋 <b>Danh sách các Terminal đang mở:</b>\n"

# System Information
MSG_STATUS_HEADER = "🖥️ <b>TRẠNG THÁI HỆ THỐNG MÁY CHỦ:</b>\n"
MSG_WHOAMI = (
    "👤 <b>THÔNG TIN ĐỊNH DANH:</b>\n"
    "• Telegram ID: <code>{user_id}</code>\n"
    "• Chế độ thực thi: <b>{mode}</b>\n"
    "• Phiên làm việc: <b>{session_status}</b>\n"
    "• Thời gian phiên còn lại: <b>{remaining_time}</b>\n"
    "• Terminal đang chọn: <b>#{active_terminal}</b>"
)
MSG_KILL_USAGE = "ℹ️ <b>Cú pháp:</b> <code>/kill &lt;JOB_ID&gt;</code>"
MSG_KILL_SUCCESS = "🛑 <b>Đã dừng tác vụ <code>{job_id}</code> thành công.</b>"
MSG_KILL_FAILED = "❌ <b>Không tìm thấy tác vụ <code>{job_id}</code> hoặc tác vụ đã kết thúc.</b>"

# Help Message
MSG_HELP_HEADER = (
    "📖 <b>HƯỚNG DẪN SỬ DỤNG TELEGRAM SERVER BOT</b>\n\n"
    "<b>Lệnh quản trị cơ bản:</b>\n"
    "• <code>/login MÃ_OTP</code>: Đăng nhập xác thực 2 bước\n"
    "• <code>/logout</code>: Kết thúc phiên làm việc ngay lập tức\n"
    "• <code>/status</code>: Xem trạng thái hệ thống (uptime, RAM, đĩa)\n"
    "• <code>/whoami</code>: Xem quyền hạn và phiên làm việc\n"
    "• <code>/jobs</code>: Xem các tác vụ đang chạy ngầm\n"
    "• <code>/kill ID</code>: Dừng một tác vụ đang chạy\n\n"
    "<b>Thực thi lệnh:</b>\n"
    "• <code>/run &lt;lệnh&gt; [tham_số...]</code>: Chạy lệnh theo chính sách\n\n"
    "<b>Điều khiển Terminal tương tác (Prefix dấu chấm):</b>\n"
    "• <code>.stop</code>: Ngắt lệnh và dừng trả kết quả (tương đương Ctrl+C)\n"
    "• <code>.new</code> hoặc <code>.n</code>: Mở terminal mới (tối đa 10)\n"
    "• <code>.t1</code> .. <code>.t10</code>: Chuyển sang terminal được đánh số\n"
    "• <code>.terminals</code> hoặc <code>.list</code>: Danh sách terminal đang mở\n"
    "• <code>.close [ID]</code>: Đóng terminal\n\n"
    "<b>Chế độ hiện tại của bạn:</b> <code>{mode}</code>\n"
)
