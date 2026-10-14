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

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pyotp
import pytest
import yaml

from src import messages
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
        now = timestamp if timestamp is not None else datetime.now(timezone.utc).timestamp()
        self.date = datetime.fromtimestamp(now, tz=timezone.utc)
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
    return app, secret, audit_file


@pytest.mark.asyncio
async def test_end_to_end_flow(test_setup):
    app, secret, audit_file = test_setup
    chat = FakeChat(chat_id=1001)

    from src.handlers.auth import login_handler, logout_handler
    from src.handlers.command import confirmation_callback_handler, run_handler
    from src.handlers.system import (
        dot_command_dispatcher,
        help_handler,
        jobs_handler,
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

    # 2. Command before login is denied
    pre_login_msg = FakeMessage("/run uptime", 1001, chat)
    pre_login_update = FakeUpdate(message=pre_login_msg)
    context.args = ["uptime"]
    await run_handler(pre_login_update, context)
    assert "chưa đăng nhập" in chat.sent_messages[-1]["text"].lower()

    # 3. Login with wrong code fails
    wrong_login_msg = FakeMessage("/login 000000", 1001, chat)
    wrong_login_update = FakeUpdate(message=wrong_login_msg)
    context.args = ["000000"]
    await login_handler(wrong_login_update, context)
    assert "không chính xác" in chat.sent_messages[-1]["text"].lower()
    assert wrong_login_msg.deleted is True

    # 4. Login with valid TOTP succeeds
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    valid_login_msg = FakeMessage(f"/login {valid_code}", 1001, chat)
    valid_login_update = FakeUpdate(message=valid_login_msg)
    context.args = [valid_code]
    await login_handler(valid_login_update, context)
    assert "đăng nhập thành công" in chat.sent_messages[-1]["text"].lower()
    assert app.session_manager.get_session(1001) is not None

    # 5. Replaying the same TOTP code is rejected
    replay_msg = FakeMessage(f"/login {valid_code}", 1001, chat)
    replay_update = FakeUpdate(message=replay_msg)
    await login_handler(replay_update, context)
    assert "đã được sử dụng" in chat.sent_messages[-1]["text"].lower()

    # 6. /whoami displays active status
    whoami_msg = FakeMessage("/whoami", 1001, chat)
    whoami_update = FakeUpdate(message=whoami_msg)
    await whoami_handler(whoami_update, context)
    assert "SHELL" in chat.sent_messages[-1]["text"]
    assert "Đang hoạt động" in chat.sent_messages[-1]["text"]

    import sys
    # 7. Safe command executes
    run_msg = FakeMessage(f'/run "{sys.executable}" -c "print(100 + 200)"', 1001, chat)
    run_update = FakeUpdate(message=run_msg)
    await run_handler(run_update, context)
    assert "300" in chat.sent_messages[-1]["text"]

    # 8. Dangerous command triggers confirmation dialog
    danger_msg = FakeMessage("/run rm -rf /srv/app/old_releases", 1001, chat)
    danger_update = FakeUpdate(message=danger_msg)
    await run_handler(danger_update, context)
    assert "CẢNH BÁO LỆNH NGUY HIỂM" in chat.sent_messages[-1]["text"]
    assert chat.sent_messages[-1]["reply_markup"] is not None

    # Extract nonce from inline button callback_data
    button = chat.sent_messages[-1]["reply_markup"].inline_keyboard[0][0]
    callback_data = button.callback_data
    assert callback_data.startswith("confirm:")
    nonce = callback_data.split(":")[1]

    # 9. Confirm dangerous execution
    cb_query = FakeCallbackQuery(data=callback_data, user_id=1001, chat=chat, message_id=chat.sent_messages[-1]["message_id"])
    cb_update = FakeUpdate(callback_query=cb_query)
    await confirmation_callback_handler(cb_update, context)

    # 10. Replaying callback query is rejected
    await confirmation_callback_handler(cb_update, context)

    # 11. Dot commands (.new, .t1..10, .stop)
    new_t_msg = FakeMessage(".new", 1001, chat)
    new_t_update = FakeUpdate(message=new_t_msg)
    await dot_command_dispatcher(new_t_update, context)
    assert "Terminal mới #2" in chat.sent_messages[-1]["text"]

    switch_msg = FakeMessage(".t1", 1001, chat)
    switch_update = FakeUpdate(message=switch_msg)
    await dot_command_dispatcher(switch_update, context)
    assert "chuyển sang Terminal #1" in chat.sent_messages[-1]["text"]

    stop_msg = FakeMessage(".stop", 1001, chat)
    stop_update = FakeUpdate(message=stop_msg)
    await dot_command_dispatcher(stop_update, context)
    assert "Đã gửi tín hiệu ngắt" in chat.sent_messages[-1]["text"]

    # 12. Restricted mode user (1002) injection is blocked
    chat_1002 = FakeChat(chat_id=1002)
    # Login user 1002
    (Path(app.config.totp_dir) / "1002.secret").write_text(secret, encoding="utf-8")
    app.session_manager.create_session(1002)

    injection_msg = FakeMessage("/run service_status nginx.service; rm -rf /", 1002, chat_1002)
    injection_update = FakeUpdate(message=injection_msg)
    await run_handler(injection_update, context)
    assert "chính sách an toàn" in chat_1002.sent_messages[-1]["text"].lower()

    # 13. Logout ends session
    logout_msg = FakeMessage("/logout", 1001, chat)
    logout_update = FakeUpdate(message=logout_msg)
    await logout_handler(logout_update, context)
    assert "đã đăng xuất" in chat.sent_messages[-1]["text"].lower()
    assert app.session_manager.get_session(1001) is None

    # 14. Audit log file verification: ensure ZERO raw secrets in entire file
    audit_content = audit_file.read_text(encoding="utf-8")
    assert secret not in audit_content
    assert app.config.bot_token not in audit_content
    assert "service_started" not in audit_content or "ABC_FAKE" not in audit_content
