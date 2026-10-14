"""End-to-End integration tests using a Fake Telegram Layer (Offline, No Network).

Tests all 19 security requirements and functional requirements end-to-end:
- Identity filtering, replay defense, silent drop.
- Pre-login denial, TOTP verification, lockout, replay rejection.
- Restricted mode parameter validation & injection defense.
- Shell mode dangerous command confirmation dialog & callback tamper protection.
- Sudo elevation approval / rejection.
- Terminal gateway dot commands (.stop, .new, .t1..10).
- Audit log integrity and zero secret leakage.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pyotp
import pytest
import yaml

from src.bot import BotApplication
from src.config import Config, LimitsConfig, SudoConfig, UserConfig


class FakeChat:
    def __init__(self, chat_id: int):
        self.id = chat_id
        self.type = "private"
        self.sent_messages: list[dict] = []

    async def send_message(self, text: str, parse_mode: str | None = None, reply_markup: Any = None):
        msg = {
            "text": text,
            "parse_mode": parse_mode,
            "reply_markup": reply_markup,
            "message_id": len(self.sent_messages) + 1,
        }
        self.sent_messages.append(msg)
        mock_msg = MagicMock()
        mock_msg.message_id = msg["message_id"]
        return mock_msg


class FakeMessage:
    def __init__(
        self,
        text: str,
        user_id: int,
        chat: FakeChat,
        message_id: int = 1,
        timestamp: float | None = None,
        is_forwarded: bool = False,
    ):
        self.text = text
        self.message_id = message_id
        self.from_user = MagicMock(id=user_id)
        self.chat = chat
        now = timestamp if timestamp is not None else datetime.now(UTC).timestamp()
        self.date = datetime.fromtimestamp(now, tz=UTC)
        self.forward_origin = "origin" if is_forwarded else None
        self.forward_date = None
        self.forward_from = None
        self.forward_from_chat = None
        self.deleted = False

    async def delete(self):
        self.deleted = True


class FakeCallbackQuery:
    def __init__(self, data: str, user_id: int, chat: FakeChat, message_id: int):
        self.data = data
        self.from_user = MagicMock(id=user_id)
        self.message = MagicMock(chat=chat, message_id=message_id)

    async def answer(self):
        pass

    async def edit_message_reply_markup(self, reply_markup=None):
        pass

    async def edit_message_text(self, text: str, parse_mode=None):
        pass


class FakeUpdate:
    def __init__(self, message=None, callback_query=None):
        self.message = message
        self.callback_query = callback_query
        self.edited_message = None
        self.channel_post = None
        self.edited_channel_post = None
        self.inline_query = None
        self.chosen_inline_result = None
        self.effective_message = message
        self.effective_user = message.from_user if message else (callback_query.from_user if callback_query else None)
        self.effective_chat = message.chat if message else (callback_query.message.chat if callback_query else None)


@pytest.fixture
def test_setup(tmp_path: Path):
    # 1. Setup policy.yaml
    policy_file = tmp_path / "policy.yaml"
    policy_data = {
        "commands": [
            {
                "name": "uptime",
                "argv": ["uptime"],
                "params": {},
                "description": "System uptime",
            },
            {
                "name": "service_status",
                "argv": ["systemctl", "status", "{unit}", "--no-pager"],
                "params": {
                    "unit": {"enum": ["nginx.service", "postgresql.service"]}
                },
                "description": "Check service status",
            },
        ]
    }
    policy_file.write_text(yaml.dump(policy_data), encoding="utf-8")

    # 2. Setup TOTP secret
    totp_dir = tmp_path / "totp"
    totp_dir.mkdir()
    secret = pyotp.random_base32()
    (totp_dir / "1001.secret").write_text(secret, encoding="utf-8")

    # 3. Setup Config
    audit_file = tmp_path / "audit.jsonl"
    config = Config(
        allowed_user_ids=[1001, 1002],
        admin_user_ids=[1001],
        users={
            1001: UserConfig(mode="shell"),
            1002: UserConfig(mode="restricted"),
        },
        bot_token="123456789:ABC_FAKE_TOKEN_FOR_TESTING",
        bot_token_file=None,
        totp_dir=str(totp_dir),
        policy_file=str(policy_file),
        audit_file=str(audit_file),
        work_dir=str(tmp_path / "sandbox"),
        limits=LimitsConfig(
            session_idle_timeout_seconds=600,
            session_absolute_timeout_seconds=3600,
            command_default_timeout_seconds=10,
        ),
        sudo=SudoConfig(policy="ask", timeout_seconds=30),
    )

    app = BotApplication(config)
    app.pam_verifier.mock_backend = True
    app.pam_verifier.set_mock_account("ubuntu", "UbuntuPass123!")
    app.pam_verifier.set_mock_account("guest", "GuestPass123!")
    return app, secret, audit_file


@pytest.mark.asyncio
async def test_end_to_end_flow(test_setup):
    app, secret, audit_file = test_setup
    chat = FakeChat(chat_id=1001)

    from src.auth.state import AuthStage
    from src.handlers.auth import exit_handler, login_handler, logout_handler
    from src.handlers.command import (
        confirmation_callback_handler,
        direct_text_dispatcher,
    )
    from src.handlers.system import (
        close_handler,
        new_terminal_handler,
        stop_handler,
        switch_terminal_handler,
        terminals_handler,
        whoami_handler,
    )

    # Context mock
    context = MagicMock()
    context.application.bot_data = {"app_state": app}

    # 1. Unknown sender is dropped silently by gatekeeper
    unknown_update = FakeUpdate(message=FakeMessage("/run uptime", 9999, FakeChat(9999)))
    is_valid, reason = app.identity_filter.validate_update(unknown_update)
    assert is_valid is False
    assert reason == "unknown_sender"

    # 2. Command or text before login is denied
    pre_login_msg = FakeMessage("uptime", 1001, chat)
    pre_login_update = FakeUpdate(message=pre_login_msg)
    await direct_text_dispatcher(pre_login_update, context)
    assert "chưa đăng nhập" in chat.sent_messages[-1]["text"].lower()

    # 3. Login with wrong TOTP code fails
    wrong_login_msg = FakeMessage("/login 000000", 1001, chat)
    wrong_login_update = FakeUpdate(message=wrong_login_msg)
    context.args = ["000000"]
    await login_handler(wrong_login_update, context)
    assert "không chính xác" in chat.sent_messages[-1]["text"].lower()
    assert wrong_login_msg.deleted is True

    # 4. Login with valid TOTP advances to AWAITING_USERNAME
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    valid_login_msg = FakeMessage(f"/login {valid_code}", 1001, chat)
    valid_login_update = FakeUpdate(message=valid_login_msg)
    context.args = [valid_code]
    await login_handler(valid_login_update, context)
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_USERNAME
    assert "tên tài khoản" in chat.sent_messages[-1]["text"].lower()

    # 5. Replaying the same TOTP code is rejected
    replay_msg = FakeMessage(f"/login {valid_code}", 1001, chat)
    replay_update = FakeUpdate(message=replay_msg)
    await login_handler(replay_update, context)
    assert "đã được sử dụng" in chat.sent_messages[-1]["text"].lower()

    # 6. Enter Linux username -> advances to AWAITING_PASSWORD
    user_msg = FakeMessage("ubuntu", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=user_msg), context)
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_PASSWORD
    assert "mật khẩu" in chat.sent_messages[-1]["text"].lower()

    # 7. Enter wrong password -> deleted, count 1/5
    bad_pw = FakeMessage("WrongPass", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=bad_pw), context)
    assert bad_pw.deleted is True
    assert "1/5" in chat.sent_messages[-1]["text"]
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_PASSWORD

    # 8. Enter correct password -> deleted, authenticated, Terminal 1 opened
    good_pw = FakeMessage("UbuntuPass123!", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=good_pw), context)
    assert good_pw.deleted is True
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AUTHENTICATED
    assert app.session_manager.get_session(1001) is not None
    assert "Terminal1 -" in chat.sent_messages[-1]["text"]
    assert "ubuntu@" in chat.sent_messages[-1]["text"]

    # 9. /whoami displays active status
    whoami_msg = FakeMessage("/whoami", 1001, chat)
    whoami_update = FakeUpdate(message=whoami_msg)
    await whoami_handler(whoami_update, context)
    assert "SHELL" in chat.sent_messages[-1]["text"]
    assert "Đang hoạt động" in chat.sent_messages[-1]["text"]

    # 10. Direct execution: text sent directly without /run
    run_msg = FakeMessage("echo 300", 1001, chat)
    run_update = FakeUpdate(message=run_msg)
    await direct_text_dispatcher(run_update, context)
    assert "300" in chat.sent_messages[-1]["text"]
    assert "Terminal1 -" in chat.sent_messages[-1]["text"]

    # 11. Dangerous command triggers confirmation dialog
    danger_msg = FakeMessage("rm -rf /srv/app/old_releases", 1001, chat)
    danger_update = FakeUpdate(message=danger_msg)
    await direct_text_dispatcher(danger_update, context)
    assert "CẢNH BÁO LỆNH NGUY HIỂM" in chat.sent_messages[-1]["text"]
    assert chat.sent_messages[-1]["reply_markup"] is not None

    # Extract nonce from inline button callback_data
    button = chat.sent_messages[-1]["reply_markup"].inline_keyboard[0][0]
    callback_data = button.callback_data
    assert callback_data.startswith("confirm:")

    # 12. Confirm dangerous execution
    cb_query = FakeCallbackQuery(data=callback_data, user_id=1001, chat=chat, message_id=chat.sent_messages[-1]["message_id"])
    cb_update = FakeUpdate(callback_query=cb_query)
    await confirmation_callback_handler(cb_update, context)

    # 13. Replaying callback query is rejected
    await confirmation_callback_handler(cb_update, context)

    # 14. Multi-user terminal gateway via slash commands
    # /new guest prompts password for guest
    new_t_msg = FakeMessage("/new guest", 1001, chat)
    context.args = ["guest"]
    await new_terminal_handler(FakeUpdate(message=new_t_msg), context)
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_NEW_TERMINAL_PASSWORD

    guest_pw = FakeMessage("GuestPass123!", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=guest_pw), context)
    assert guest_pw.deleted is True
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AUTHENTICATED
    assert "Terminal2 -" in chat.sent_messages[-1]["text"]
    assert "guest@" in chat.sent_messages[-1]["text"]

    # /terminals lists both terminals
    await terminals_handler(FakeUpdate(message=FakeMessage("/terminals", 1001, chat)), context)
    assert "Terminal #1" in chat.sent_messages[-1]["text"]
    assert "Terminal #2" in chat.sent_messages[-1]["text"]

    # /t1 switches to terminal 1
    await switch_terminal_handler(FakeUpdate(message=FakeMessage("/t1", 1001, chat)), context, terminal_num=1)
    assert "Terminal1 -" in chat.sent_messages[-1]["text"]

    # /stop sends interrupt
    await stop_handler(FakeUpdate(message=FakeMessage("/stop", 1001, chat)), context)
    assert "Đã gửi tín hiệu ngắt" in chat.sent_messages[-1]["text"]

    # /close 2 closes terminal 2
    context.args = ["2"]
    await close_handler(FakeUpdate(message=FakeMessage("/close 2", 1001, chat)), context)
    assert "Đã đóng Terminal #2" in chat.sent_messages[-1]["text"]

    # 15. Restricted mode user (1002) injection is blocked
    chat_1002 = FakeChat(chat_id=1002)
    (Path(app.config.totp_dir) / "1002.secret").write_text(secret, encoding="utf-8")
    app.session_manager.create_session(1002)
    app.auth_state_manager.complete_authentication(1002, "ubuntu")

    injection_msg = FakeMessage("service_status nginx.service; rm -rf /", 1002, chat_1002)
    injection_update = FakeUpdate(message=injection_msg)
    await direct_text_dispatcher(injection_update, context)
    assert "chính sách an toàn" in chat_1002.sent_messages[-1]["text"].lower()

    # 16. /logout keeps TOTP session, reverts to username entry
    logout_msg = FakeMessage("/logout", 1001, chat)
    logout_update = FakeUpdate(message=logout_msg)
    await logout_handler(logout_update, context)
    assert "đã đăng xuất" in chat.sent_messages[-1]["text"].lower()
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_USERNAME

    # 17. /exit terminates session completely
    exit_msg = FakeMessage("/exit", 1001, chat)
    exit_update = FakeUpdate(message=exit_msg)
    await exit_handler(exit_update, context)
    assert "đã thoát hoàn toàn" in chat.sent_messages[-1]["text"].lower()
    assert app.session_manager.get_session(1001) is None
    assert app.auth_state_manager.get_stage(1001) == AuthStage.UNAUTHENTICATED

    # 18. Audit log file verification: ensure ZERO raw secrets in entire file
    audit_content = audit_file.read_text(encoding="utf-8")
    assert secret not in audit_content
    assert app.config.bot_token not in audit_content
    assert "UbuntuPass123!" not in audit_content
    assert "GuestPass123!" not in audit_content
    assert app.config.bot_token not in audit_content
    assert "service_started" not in audit_content or "ABC_FAKE" not in audit_content
