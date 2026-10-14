"""Tests for direct text command execution (without /run), multi-step login flow, and password deletion."""

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
    totp_path = tmp_path / "totp"
    totp_path.mkdir(parents=True, exist_ok=True)
    work_path = tmp_path / "work"
    work_path.mkdir(parents=True, exist_ok=True)
    config = Config(
        allowed_user_ids=[1001],
        admin_user_ids=[1001],
        users={1001: UserConfig(mode="shell")},
        bot_token="fake_token",
        bot_token_file=None,
        totp_dir=str(totp_path),
        policy_file=str(policy_file),
        audit_file=str(tmp_path / "audit.jsonl"),
        work_dir=str(work_path),
        limits=LimitsConfig(),
        sudo=SudoConfig(),
    )
    app = BotApplication(config)
    # Enable mock PAM backend
    app.pam_verifier.mock_backend = True
    app.pam_verifier.set_mock_account("ubuntu", "UbuntuPass123!")
    app.pam_verifier.set_mock_account("guest", "GuestPass123!")
    return app


@pytest.mark.asyncio
async def test_full_login_dialog_flow_and_retry(test_app):
    app = test_app
    chat = FakeChat(chat_id=1001)

    from src.handlers.auth import login_handler
    from src.handlers.command import direct_text_dispatcher

    context = MagicMock()
    context.application.bot_data = {"app_state": app}

    # 1. Unauthenticated direct text is rejected
    msg1 = FakeMessage("ls -la", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=msg1), context)
    assert "chưa đăng nhập" in chat.sent_messages[-1]["text"].lower()

    # 2. Step 1: /login TOTP
    # Setup mock TOTP
    import pyotp
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    (test_app.totp_manager.totp_dir / "1001.secret").write_text(secret, encoding="utf-8")
    valid_code = totp.now()

    context.args = [valid_code]
    login_msg = FakeMessage(f"/login {valid_code}", 1001, chat)
    await login_handler(FakeUpdate(message=login_msg), context)
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_USERNAME
    assert "tên tài khoản" in chat.sent_messages[-1]["text"].lower()

    # 3. Step 2: Enter username
    user_msg = FakeMessage("ubuntu", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=user_msg), context)
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_PASSWORD
    assert app.auth_state_manager.get_pending_username(1001) == "ubuntu"
    assert "mật khẩu" in chat.sent_messages[-1]["text"].lower()

    # 4. Step 3: Enter wrong password -> retry 1/5
    wrong_pass_msg = FakeMessage("WrongPass", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=wrong_pass_msg), context)
    assert wrong_pass_msg.deleted is True
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_PASSWORD
    assert "1/5" in chat.sent_messages[-1]["text"]

    # 5. Enter correct password -> completes login, opens Terminal #1
    correct_pass_msg = FakeMessage("UbuntuPass123!", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=correct_pass_msg), context)
    assert correct_pass_msg.deleted is True
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AUTHENTICATED
    assert "Terminal1 -" in chat.sent_messages[-1]["text"]
    assert "ubuntu@" in chat.sent_messages[-1]["text"]

    # 6. Direct execution: user sends command directly without /run
    cmd_msg = FakeMessage("echo 999", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=cmd_msg), context)
    assert "999" in chat.sent_messages[-1]["text"]
    assert "Terminal1 -" in chat.sent_messages[-1]["text"]


@pytest.mark.asyncio
async def test_password_exceed_five_failures_reverts_to_username(test_app):
    app = test_app
    chat = FakeChat(chat_id=1001)

    from src.handlers.command import direct_text_dispatcher

    context = MagicMock()
    context.application.bot_data = {"app_state": app}

    # Set state to AWAITING_PASSWORD
    app.auth_state_manager.set_stage(1001, AuthStage.AWAITING_PASSWORD, pending_username="ubuntu")

    # Fail 5 times
    for i in range(1, 5):
        msg = FakeMessage(f"bad_{i}", 1001, chat)
        await direct_text_dispatcher(FakeUpdate(message=msg), context)
        assert f"{i}/5" in chat.sent_messages[-1]["text"]
        assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_PASSWORD

    # 5th failure
    msg5 = FakeMessage("bad_5", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=msg5), context)
    assert "5 lần" in chat.sent_messages[-1]["text"]
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_USERNAME


@pytest.mark.asyncio
async def test_new_terminal_with_password_flow(test_app):
    app = test_app
    chat = FakeChat(chat_id=1001)

    from src.handlers.command import direct_text_dispatcher
    from src.handlers.system import new_terminal_handler

    context = MagicMock()
    context.application.bot_data = {"app_state": app}

    # 1. Start authenticated as ubuntu
    app.auth_state_manager.complete_authentication(1001, "ubuntu")
    app.session_manager.create_session(1001)
    await app.pty_session_manager.create_terminal(1001, "ubuntu")

    # 2. Run /new guest
    context.args = ["guest"]
    msg_new = FakeMessage("/new guest", 1001, chat)
    await new_terminal_handler(FakeUpdate(message=msg_new), context)
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_NEW_TERMINAL_PASSWORD
    assert "guest" in chat.sent_messages[-1]["text"]

    # 3. Enter wrong password
    wrong_pw = FakeMessage("WrongGuestPass", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=wrong_pw), context)
    assert wrong_pw.deleted is True
    assert "không chính xác" in chat.sent_messages[-1]["text"].lower()
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AUTHENTICATED

    # 4. Run /new guest again and enter correct password
    await new_terminal_handler(FakeUpdate(message=msg_new), context)
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AWAITING_NEW_TERMINAL_PASSWORD

    correct_pw = FakeMessage("GuestPass123!", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=correct_pw), context)
    assert correct_pw.deleted is True
    assert app.auth_state_manager.get_stage(1001) == AuthStage.AUTHENTICATED
    assert "Terminal2 -" in chat.sent_messages[-1]["text"]
    assert "guest@" in chat.sent_messages[-1]["text"]

    # 5. Direct execution on Terminal 2
    cmd_msg = FakeMessage("echo hello_guest", 1001, chat)
    await direct_text_dispatcher(FakeUpdate(message=cmd_msg), context)
    assert "hello_guest" in chat.sent_messages[-1]["text"]
    assert "Terminal2 -" in chat.sent_messages[-1]["text"]
