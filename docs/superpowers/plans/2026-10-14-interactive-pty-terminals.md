# Interactive PTY Terminals & Multi-User Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Chuyển đổi Telegram Linux Server Administration Bot sang mô hình Interactive Shell Gateway: loại bỏ prefix `/run` (thực thi trực tiếp tin nhắn thông thường), dồn toàn bộ lệnh điều khiển về slash commands (`/stop`, `/new`, `/t1`..`/t10`, `/terminals`, `/close`), phân biệt `/logout` và `/exit`, bổ sung luồng xác thực đa tầng (TOTP -> Username -> PAM Password verification trực tiếp qua PTY không lưu mật khẩu), hỗ trợ đa terminal theo user Linux độc lập, và hiển thị prompt chuẩn trích xuất trực tiếp từ terminal.

**Architecture:** 
- Mô hình máy trạng thái phiên (`AuthState`): Quản lý luồng đăng nhập 3 bước, retry mật khẩu tối đa 5 lần rồi lùi về nhập username, phân biệt `/logout` (giữ TOTP, về bước nhập user) và `/exit` (thoát hoàn toàn).
- `LinuxPAMVerifier`: Xác thực mật khẩu tài khoản Linux trực tiếp qua tiến trình PTY `su - <user>`, xóa ngay tin nhắn Telegram và không bao giờ lưu trữ mật khẩu.
- `PTYSessionManager`: Quản lý 1-10 interactive shell sessions, gắn với user Linux độc lập, trích xuất prompt `PS1` thực tế từ PTY và định dạng chuẩn `Terminal<N> - <thời gian>\n<prompt pty>`.
- Message Router: Tin nhắn có prefix `/` định tuyến tới slash command handlers; tin nhắn thông thường chuyển thẳng vào active terminal PTY.

**Tech Stack:** Python 3.12+, `python-telegram-bot` v21.x, Linux PTY (`pty`, `termios`, `fcntl` / `openpty`), native C executor fallback, `pytest`, `pytest-asyncio`.

**Spec:** `docs/superpowers/specs/2026-10-14-interactive-pty-terminals-design.md`

## Global Constraints

- Không lưu mật khẩu của người dùng vào bất kỳ tệp cấu hình, đĩa hoặc RAM lâu dài.
- Tin nhắn Telegram chứa mật khẩu phải được gọi `delete()` xóa ngay lập tức khi vừa nhận.
- Prompt hiển thị phải trích xuất trực tiếp từ terminal PTY thực tế, không tự định nghĩa.
- Định dạng prompt: `Terminal<N> - <dd/mm/yyyy hh:mm:ss>\n<prompt pty>`.
- Nhập sai mật khẩu < 5 lần: cho phép nhập lại mật khẩu; nhập sai >= 5 lần: quay về bước nhập tên tài khoản.
- `/logout`: quay về bước chọn người dùng (giữ TOTP).
- `/exit`: thoát hoàn toàn, cần `/start` hoặc `/login` từ đầu.
- Tất cả lệnh điều khiển gateway sử dụng prefix `/` (`/stop`, `/new`, `/t1`..`/t10`, `/terminals`, `/close`). Bỏ hoàn toàn prefix `.` và prefix `/run`.
- Mã nguồn và định danh bằng tiếng Anh; thông điệp bot, tài liệu và giao tiếp bằng tiếng Việt.

## Review Focus

1. Kiểm tra an toàn khi `delete()` tin nhắn mật khẩu trên Telegram (xử lý ngoại lệ nếu bot thiếu quyền xóa tin nhắn).
2. Tách biệt hoàn toàn biến môi trường và tiến trình giữa các terminal của các user Linux khác nhau (`root` vs `guest`).
3. Ngắt an toàn `SIGINT` (Ctrl+C) qua `/stop` mà không làm chết shell PTY chính.
4. Trích xuất chính xác chuỗi prompt PTY ngay cả khi lệnh có output dài nhiều trang hoặc không có output.
5. Bảo vệ chống race condition khi chuyển đổi nhanh giữa các terminal `/t1`..`/t10` trong lúc có dữ liệu đang stream.

---

### Task 1: Máy trạng thái Xác thực Đa tầng (`AuthStateManager`)

**Files:**
- Create: `src/auth/state.py`
- Test: `tests/test_auth_state.py`

**Interfaces:**
- Produces: `AuthStage` enum (`UNAUTHENTICATED`, `AWAITING_USERNAME`, `AWAITING_PASSWORD`, `AUTHENTICATED`, `AWAITING_NEW_TERMINAL_PASSWORD`), `AuthStateManager` class (`set_stage()`, `get_stage()`, `record_password_failure()`, `reset_failures()`, `logout_to_username()`, `exit_to_unauthenticated()`).

- [ ] **Step 1: Write the failing test for `AuthStateManager`**

```python
def test_auth_state_retry_and_lockout_to_username():
    from src.auth.state import AuthStage, AuthStateManager
    mgr = AuthStateManager()
    user_id = 1001
    assert mgr.get_stage(user_id) == AuthStage.UNAUTHENTICATED

    # Pass TOTP -> AWAITING_USERNAME
    mgr.set_stage(user_id, AuthStage.AWAITING_USERNAME)
    assert mgr.get_stage(user_id) == AuthStage.AWAITING_USERNAME

    # Enter username -> AWAITING_PASSWORD
    mgr.set_stage(user_id, AuthStage.AWAITING_PASSWORD, pending_username="root")
    assert mgr.get_stage(user_id) == AuthStage.AWAITING_PASSWORD
    assert mgr.get_pending_username(user_id) == "root"

    # Fail password 4 times -> still AWAITING_PASSWORD
    for i in range(1, 5):
        next_stage, attempts = mgr.record_password_failure(user_id)
        assert next_stage == AuthStage.AWAITING_PASSWORD
        assert attempts == i

    # 5th failure -> reverts to AWAITING_USERNAME
    next_stage, attempts = mgr.record_password_failure(user_id)
    assert next_stage == AuthStage.AWAITING_USERNAME
    assert attempts == 5
    assert mgr.get_stage(user_id) == AuthStage.AWAITING_USERNAME
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\pytest.exe tests/test_auth_state.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.auth.state'`

- [ ] **Step 3: Implement `src/auth/state.py`**

Triển khai `AuthStage` và `AuthStateManager` với quản lý trạng thái in-memory, theo dõi `pending_username`, `password_failure_count`, `logout_to_username()`, `exit_to_unauthenticated()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\pytest.exe tests/test_auth_state.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/auth/state.py tests/test_auth_state.py
git commit -m "feat(auth): implement multi-step AuthStateManager with password retry loop"
```

---

### Task 2: Trình Xác thực Linux PAM/PTY Không lưu Mật khẩu (`LinuxPAMVerifier`)

**Files:**
- Create: `src/auth/pam_verifier.py`
- Test: `tests/test_pam_verifier.py`

**Interfaces:**
- Consumes: Username & Password strings in memory.
- Produces: `LinuxPAMVerifier.verify_credentials(username: str, password: str) -> tuple[bool, str]`. Không bao giờ lưu trữ mật khẩu, đẩy trực tiếp vào tiến trình xác thực `su - <user>` qua pipe/PTY.

- [ ] **Step 1: Write the failing test for `LinuxPAMVerifier`**

```python
def test_pam_verifier_flow():
    from src.auth.pam_verifier import LinuxPAMVerifier
    verifier = LinuxPAMVerifier(mock_backend=True)
    verifier.set_mock_account("guest", "ValidPass123!")

    # Correct credentials
    success, err = verifier.verify_credentials("guest", "ValidPass123!")
    assert success is True
    assert err == ""

    # Wrong credentials
    success, err = verifier.verify_credentials("guest", "WrongPass")
    assert success is False
    assert "authentication_failed" in err.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\pytest.exe tests/test_pam_verifier.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.auth.pam_verifier'`

- [ ] **Step 3: Implement `src/auth/pam_verifier.py`**

Hiện thực kiểm tra tài khoản qua Linux `su - <username>` / PAM helper, và mock backend để kiểm thử độc lập không phụ thuộc môi trường host. Đảm bảo mật khẩu bị xóa khỏi bộ nhớ ngay khi hoàn thành kiểm tra.

- [ ] **Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\pytest.exe tests/test_pam_verifier.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/auth/pam_verifier.py tests/test_pam_verifier.py
git commit -m "feat(auth): implement LinuxPAMVerifier zero-storage password verification"
```

---

### Task 3: Quản lý Phiên Terminal PTY Đa Người dùng & Bắt Prompt Thực tế (`PTYSessionManager`)

**Files:**
- Create: `src/executor/pty_session.py`
- Test: `tests/test_pty_session.py`

**Interfaces:**
- Produces: `PTYTerminalSession`, `PTYSessionManager` (`create_terminal(user_id, username)`, `get_active_terminal()`, `switch_terminal(terminal_id)`, `close_terminal(terminal_id)`, `send_command(cmd)`, `interrupt_current()`, `format_terminal_prompt()`).
- Format:
  ```text
  Terminal<N> - <dd/mm/yyyy hh:mm:ss>
  <prompt pty>
  ```

- [ ] **Step 1: Write the failing test for `PTYSessionManager`**

```python
def test_pty_session_lifecycle_and_prompt_format():
    from src.executor.pty_session import PTYSessionManager
    mgr = PTYSessionManager(mock_pty=True)
    user_id = 1001

    # 1. Create Terminal 1 for root
    term1 = mgr.create_terminal(user_id=user_id, username="root")
    assert term1.terminal_id == 1
    assert term1.username == "root"

    # 2. Check prompt formatting
    prompt_str = mgr.format_terminal_prompt(user_id=user_id, terminal_id=1)
    assert prompt_str.startswith("Terminal1 - ")
    assert "root@" in prompt_str

    # 3. Create Terminal 2 for guest
    term2 = mgr.create_terminal(user_id=user_id, username="guest")
    assert term2.terminal_id == 2
    assert term2.username == "guest"

    # 4. Switch to Terminal 1
    switched = mgr.switch_terminal(user_id=user_id, terminal_id=1)
    assert switched is True
    assert mgr.get_active_terminal(user_id).username == "root"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\pytest.exe tests/test_pty_session.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.executor.pty_session'`

- [ ] **Step 3: Implement `src/executor/pty_session.py`**

Hiện thực `PTYTerminalSession` và `PTYSessionManager`: quản lý tối đa 10 terminal, trích xuất prompt thực tế từ PTY output stream, ghi nhận `login_time` định dạng `dd/mm/yyyy hh:mm:ss`, gửi lệnh và ngắt `SIGINT` (Ctrl+C).

- [ ] **Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\pytest.exe tests/test_pty_session.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/executor/pty_session.py tests/test_pty_session.py
git commit -m "feat(executor): implement PTYSessionManager with multi-user terminals and real prompt capture"
```

---

### Task 4: Chuyển đổi Bộ điều khiển sang Slash Commands (`/`) & Phân biệt `/logout` và `/exit`

**Files:**
- Modify: `src/handlers/system.py`
- Modify: `src/handlers/auth.py`
- Modify: `src/bot.py`
- Test: `tests/test_slash_terminals.py`

**Interfaces:**
- Đăng ký và xử lý: `/stop`, `/new` (user hiện tại), `/new <user>` (hỏi pass), `/t1`..`/t10`, `/terminals`, `/close`, `/logout` (về nhập user), `/exit` (thoát hoàn toàn).
- Loại bỏ hoàn toàn regex `^\.` dot command dispatcher.

- [ ] **Step 1: Write the failing test for slash commands and logout/exit**

```python
def test_slash_terminals_and_logout_vs_exit():
    # Verify /stop, /new, /t1..10, /logout, /exit behavior
    pass
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\pytest.exe tests/test_slash_terminals.py -v`
Expected: FAIL

- [ ] **Step 3: Implement slash handlers in `src/handlers/system.py`, `src/handlers/auth.py`, and `src/bot.py`**

- [ ] **Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\pytest.exe tests/test_slash_terminals.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/handlers/system.py src/handlers/auth.py src/bot.py tests/test_slash_terminals.py
git commit -m "feat(handlers): unify gateway controls under slash commands, implement distinct /logout and /exit"
```

---

### Task 5: Thực thi Lệnh Trực tiếp (Bỏ `/run`) & Cập nhật Tin nhắn Tiếng Việt (`messages.py`)

**Files:**
- Modify: `src/handlers/command.py`
- Modify: `src/messages.py`
- Test: `tests/test_direct_execution.py`

**Interfaces:**
- Message handler cho văn bản thông thường (không có prefix `/`):
  - Nếu đang ở `AWAITING_USERNAME`: xử lý username input.
  - Nếu đang ở `AWAITING_PASSWORD`: xóa tin nhắn ngay lập tức và xác thực mật khẩu.
  - Nếu đang ở `AWAITING_NEW_TERMINAL_PASSWORD`: xóa tin nhắn và xác thực mật khẩu tạo terminal mới.
  - Nếu đang ở `AUTHENTICATED`: gửi thẳng lệnh vào shell PTY của active terminal, trả về output kèm prompt chuẩn.

- [ ] **Step 1: Write the failing test for direct command execution**

```python
def test_direct_command_execution_without_run_prefix():
    # Verify non-slash text executes directly in active terminal
    pass
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\pytest.exe tests/test_direct_execution.py -v`
Expected: FAIL

- [ ] **Step 3: Implement direct execution in `src/handlers/command.py` and update `src/messages.py`**

- [ ] **Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\pytest.exe tests/test_direct_execution.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/handlers/command.py src/messages.py tests/test_direct_execution.py
git commit -m "feat(handlers): support direct command execution without /run prefix and update Vietnamese messages"
```

---

### Task 6: Kiểm thử Tích hợp End-to-End Toàn diện & Cập nhật Tài liệu (`README.md`, `SECURITY.md`)

**Files:**
- Modify: `tests/test_end_to_end.py`
- Modify: `README.md`
- Modify: `docs/SECURITY.md`
- Modify: `docs/PROGRESS.md`

- [ ] **Step 1: Update `tests/test_end_to_end.py` for full multi-step login, multi-user terminals, direct execution, `/logout`, `/exit`**
- [ ] **Step 2: Run full test suite**

Run: `.\.venv\Scripts\pytest.exe -v`
Expected: PASS 100%

- [ ] **Step 3: Run linters and security checks**

Run: `.\.venv\Scripts\ruff.exe check .` and `.\.venv\Scripts\bandit.exe -c pyproject.toml -r src/`
Expected: 0 errors, 0 security issues.

- [ ] **Step 4: Update `README.md`, `docs/SECURITY.md`, and `docs/PROGRESS.md`**
- [ ] **Step 5: Commit**

```bash
git add tests/test_end_to_end.py README.md docs/SECURITY.md docs/PROGRESS.md
git commit -m "docs & test: complete e2e verification, documentation update for interactive PTY terminals"
```
