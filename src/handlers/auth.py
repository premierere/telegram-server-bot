"""Authentication command handlers: /login and /logout."""

from __future__ import annotations

from typing import TYPE_CHECKING

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from src import messages
from src.audit import AuditEvent
from src.auth.state import AuthStage

if TYPE_CHECKING:
    from src.bot import BotApplication


async def login_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /login CODE command."""
    app: BotApplication = context.application.bot_data["app_state"]
    message = update.effective_message
    user = update.effective_user
    chat = update.effective_chat

    if not message or not user or not chat:
        return

    # Delete message containing the OTP code as quickly as possible
    try:
        await message.delete()
    except Exception:
        pass  # Telegram might not allow deleting in all contexts

    args = context.args or []
    if not args:
        await chat.send_message(messages.MSG_LOGIN_USAGE, parse_mode=ParseMode.HTML)
        return

    code = args[0].strip()

    # Verify TOTP code
    is_valid, reason = app.totp_manager.verify_code(user_id=user.id, code=code)

    if is_valid:
        # Set stage to AWAITING_USERNAME
        app.auth_state_manager.set_stage(user.id, AuthStage.AWAITING_USERNAME)

        # Log audit and alert admin
        event = AuditEvent(
            user_id=user.id,
            chat_id=chat.id,
            message_id=message.message_id,
            event_type="login_totp_verified",
            decision="allowed",
            reason="totp_verified",
        )
        alert_msg = f"🔔 <b>Thông báo:</b> Quản trị viên <code>{user.id}</code> vừa xác thực TOTP thành công. Đang chờ nhập tài khoản Linux."
        await app.audit_logger.log_and_alert(event, alert_message=alert_msg)

        await chat.send_message(
            "✅ <b>Xác thực TOTP thành công!</b>\nVui lòng nhập tên tài khoản Linux trên máy chủ (ví dụ: <code>root</code>, <code>ubuntu</code>, <code>guest</code>):",
            parse_mode=ParseMode.HTML,
        )
    elif reason.startswith("account_locked"):
        seconds = reason.split(":")[1] if ":" in reason else "300"
        event = AuditEvent(
            user_id=user.id,
            chat_id=chat.id,
            message_id=message.message_id,
            event_type="lockout",
            decision="denied",
            reason=reason,
        )
        alert_msg = f"🚨 <b>CẢNH BÁO BẢO MẬT:</b> Tài khoản <code>{user.id}</code> đã bị tạm khóa do nhập sai OTP quá số lần quy định."
        await app.audit_logger.log_and_alert(event, alert_message=alert_msg)

        await chat.send_message(
            messages.MSG_LOGIN_LOCKED.format(seconds=seconds),
            parse_mode=ParseMode.HTML,
        )
    elif reason == "code_already_used":
        event = AuditEvent(
            user_id=user.id,
            chat_id=chat.id,
            message_id=message.message_id,
            event_type="login_failed",
            decision="denied",
            reason="code_already_used",
        )
        app.audit_logger.log(event)
        await chat.send_message(messages.MSG_LOGIN_CODE_USED, parse_mode=ParseMode.HTML)
    else:
        event = AuditEvent(
            user_id=user.id,
            chat_id=chat.id,
            message_id=message.message_id,
            event_type="login_failed",
            decision="denied",
            reason=reason,
        )
        app.audit_logger.log(event)
        await chat.send_message(messages.MSG_LOGIN_FAILED, parse_mode=ParseMode.HTML)


async def logout_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /logout: close terminals, reset user account, keep TOTP active, return to username step."""
    app: BotApplication = context.application.bot_data["app_state"]
    user = update.effective_user
    chat = update.effective_chat
    message = update.effective_message

    if not user or not chat:
        return

    await app.pty_session_manager.close_all_terminals(user.id)
    app.auth_state_manager.logout_to_username(user.id)

    event = AuditEvent(
        user_id=user.id,
        chat_id=chat.id,
        message_id=message.message_id if message else None,
        event_type="logout",
        decision="allowed",
        reason="user_logout_to_username",
    )
    app.audit_logger.log(event)

    await chat.send_message(
        "🔒 <b>Đã đăng xuất khỏi tài khoản Linux.</b> Phiên xác thực TOTP vẫn còn hiệu lực.\nVui lòng nhập tên tài khoản Linux để đăng nhập tiếp:",
        parse_mode=ParseMode.HTML,
    )


async def exit_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /exit: completely terminate session, close terminals, require full /start or /login."""
    app: BotApplication = context.application.bot_data["app_state"]
    user = update.effective_user
    chat = update.effective_chat
    message = update.effective_message

    if not user or not chat:
        return

    await app.pty_session_manager.close_all_terminals(user.id)
    app.session_manager.destroy_session(user.id)
    app.auth_state_manager.exit_to_unauthenticated(user.id)

    event = AuditEvent(
        user_id=user.id,
        chat_id=chat.id,
        message_id=message.message_id if message else None,
        event_type="exit",
        decision="allowed",
        reason="user_exit_all",
    )
    app.audit_logger.log(event)

    await chat.send_message(
        "👋 <b>Đã thoát hoàn toàn khỏi hệ thống.</b>\nVui lòng sử dụng <code>/start</code> hoặc <code>/login</code> để bắt đầu lại từ đầu.",
        parse_mode=ParseMode.HTML,
    )
