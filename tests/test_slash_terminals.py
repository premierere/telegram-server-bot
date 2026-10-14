"""Tests for slash command gateway controls (/stop, /new, /t1..10, /terminals, /close, /logout, /exit)."""

from unittest.mock import MagicMock

import pytest

from src.auth.state import AuthStage
from src.bot import BotApplication
from src.config import Config, LimitsConfig, SudoConfig, UserConfig
from tests.test_end_to_end import FakeChat, FakeMessage, FakeUpdate


@pytest.fixture
def test_app(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("commands: []", encoding="utf-8")
    config = Config(
        allowed_user_ids=[1001],
        admin_user_ids=[1001],
        users={1001: UserConfig(mode="shell")},
        bot_token="fake_token",
        bot_token_file=None,
        totp_dir=str(tmp_path / "totp"),
        policy_file=str(policy_file),
        audit_file=str(tmp_path / "audit.jsonl"),
        work_dir=str(tmp_path / "work"),
        limits=LimitsConfig(),
        sudo=SudoConfig(),
    )
    app = BotApplication(config)
    return app


@pytest.mark.asyncio
async def test_slash_terminals_lifecycle(test_app):
    app = test_app
    chat = FakeChat(chat_id=1001)

    from src.handlers.system import (
        close_handler,
        new_terminal_handler,
        stop_handler,
        switch_terminal_handler,
        terminals_handler,
    )

    context = MagicMock()
    context.application.bot_data = {"app_state": app}

    # 1. Setup authenticated session with root user
    app.session_manager.create_session(1001)
    app.auth_state_manager.complete_authentication(1001, "root")
    await app.pty_session_manager.create_terminal(1001, "root")

    # 2. Test /terminals list
    t_msg = FakeMessage("/terminals", 1001, chat)
    context.args = []
    await terminals_handler(FakeUpdate(message=t_msg), context)
    assert "Terminal #1" in chat.sent_messages[-1]["text"]
    assert "root" in chat.sent_messages[-1]["text"]

    # 3. Test /new (no args) opens terminal for current user (root)
    new_msg = FakeMessage("/new", 1001, chat)
    await new_terminal_handler(FakeUpdate(message=new_msg), context)
    assert "Terminal2 -" in chat.sent_messages[-1]["text"]
    assert len(app.pty_session_manager.list_terminals(1001)) == 2

    # 4. Test /new guest initiates password prompt
    context.args = ["guest"]
    new_guest_msg = FakeMessage("/new guest", 1001, chat)
    await new_terminal_handler(FakeUpdate(message=new_guest_msg), context)
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_NEW_TERMINAL_PASSWORD
    assert app.auth_state_manager.get_target_new_terminal_username(1001) == "guest"
    assert "guest" in chat.sent_messages[-1]["text"].lower()
    assert "mật khẩu" in chat.sent_messages[-1]["text"].lower()

    # Reset stage for next tests
    app.auth_state_manager.set_stage(1001, AuthStage.AUTHENTICATED)

    # 5. Test /t1 switch
    context.args = []
    t1_msg = FakeMessage("/t1", 1001, chat)
    await switch_terminal_handler(FakeUpdate(message=t1_msg), context, terminal_num=1)
    assert "Terminal1 -" in chat.sent_messages[-1]["text"]
    assert app.pty_session_manager.get_active_terminal(1001).terminal_id == 1

    # 6. Test /stop
    stop_msg = FakeMessage("/stop", 1001, chat)
    await stop_handler(FakeUpdate(message=stop_msg), context)
    assert "ngắt" in chat.sent_messages[-1]["text"].lower() or "dừng" in chat.sent_messages[-1]["text"].lower()

    # 7. Test /close
    close_msg = FakeMessage("/close", 1001, chat)
    await close_handler(FakeUpdate(message=close_msg), context)
    assert len(app.pty_session_manager.list_terminals(1001)) == 1


@pytest.mark.asyncio
async def test_logout_vs_exit(test_app):
    app = test_app
    chat = FakeChat(chat_id=1001)

    from src.handlers.auth import exit_handler, logout_handler

    context = MagicMock()
    context.application.bot_data = {"app_state": app}

    # Setup session
    app.session_manager.create_session(1001)
    app.auth_state_manager.complete_authentication(1001, "root")
    await app.pty_session_manager.create_terminal(1001, "root")

    # 1. /logout: returns to AWAITING_USERNAME (keeps TOTP)
    logout_msg = FakeMessage("/logout", 1001, chat)
    await logout_handler(FakeUpdate(message=logout_msg), context)
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_USERNAME
    assert len(app.pty_session_manager.list_terminals(1001)) == 0
    assert "tên tài khoản" in chat.sent_messages[-1]["text"].lower()

    # 2. /exit: clears session completely, returns to UNAUTHENTICATED
    exit_msg = FakeMessage("/exit", 1001, chat)
    await exit_handler(FakeUpdate(message=exit_msg), context)
    assert app.auth_state_manager.get_stage(1001) == AuthStage.UNAUTHENTICATED
    assert app.session_manager.get_session(1001) is None
    assert "/login" in chat.sent_messages[-1]["text"]
