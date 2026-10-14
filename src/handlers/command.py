"""Command execution handler: /run and confirmation callbacks (dangerous & sudo)."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from src import messages
from src.audit import AuditEvent
from src.executor.terminals import TerminalState, paginate_output
from src.redaction import sanitize_output

if TYPE_CHECKING:
    from src.bot import BotApplication


async def run_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /run command under policy and safety controls."""
    app: BotApplication = context.application.bot_data["app_state"]
    message = update.effective_message
    user = update.effective_user
    chat = update.effective_chat

    if not message or not user or not chat:
        return

    # 1. Verify Active Session
    session = app.session_manager.get_session(user.id)
    if not session:
        await chat.send_message(messages.MSG_NOT_LOGGED_IN, parse_mode=ParseMode.HTML)
        return
    session.touch()

    # 2. Check Rate Limit (10 commands/min per user)
    is_allowed, wait_seconds = app.job_manager.check_rate_limit(user.id)
    if not is_allowed:
        await chat.send_message(
            messages.MSG_RATE_LIMIT_EXCEEDED.format(wait_seconds=wait_seconds),
            parse_mode=ParseMode.HTML,
        )
        return

    # 3. Check Global Concurrency Limit (max 2 active jobs)
    if not app.job_manager.can_acquire_slot():
        await chat.send_message(
            messages.MSG_CONCURRENCY_LIMIT_EXCEEDED,
            parse_mode=ParseMode.HTML,
        )
        return

    # Parse arguments after /run
    raw_text = message.text or ""
    # Extract text after '/run '
    parts = raw_text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await chat.send_message(messages.MSG_RUN_USAGE, parse_mode=ParseMode.HTML)
        return

    command_input = parts[1].strip()
    user_config = app.config.users.get(user.id)
    user_mode = user_config.mode if user_config else "restricted"

    # Record rate limit consumption
    app.job_manager.record_command_attempt(user.id)

    # 4. Handle Execution Modes
    if user_mode == "restricted":
        # Restricted Mode
        tokens = command_input.split()
        cmd_name = tokens[0]
        cmd_args = tokens[1:]

        success, resolved_argv, reason = app.policy_engine.validate_and_build_argv(cmd_name, cmd_args)
        if not success:
            event = AuditEvent(
                user_id=user.id,
                chat_id=chat.id,
                message_id=message.message_id,
                event_type="command_denied",
                command=command_input,
                decision="denied",
                reason=reason,
            )
            app.audit_logger.log(event)
            await chat.send_message(
                messages.MSG_RESTRICTED_REJECTED.format(reason=reason),
                parse_mode=ParseMode.HTML,
            )
            return

        # Sudo check
        needs_sudo = resolved_argv[0] == "sudo" if resolved_argv else False
        if needs_sudo and app.config.sudo.policy == "ask":
            await _prompt_sudo_confirmation(app, chat, user, message, resolved_argv=resolved_argv)
            return

        # Execute restricted command
        await _execute_and_stream(app, chat, user, message, argv=resolved_argv)

    else:
        # Shell Mode
        # Check dangerous pattern list
        if app.policy_engine.is_dangerous_shell_command(command_input):
            # Prompt dangerous confirmation
            await _prompt_dangerous_confirmation(app, chat, user, message, shell_command=command_input)
            return

        # Check sudo in shell command
        needs_sudo = command_input.strip().startswith("sudo ")
        if needs_sudo and app.config.sudo.policy == "ask":
            await _prompt_sudo_confirmation(app, chat, user, message, shell_command=command_input)
            return
        elif needs_sudo and app.config.sudo.policy == "disabled":
            await chat.send_message(messages.MSG_SUDO_DISABLED, parse_mode=ParseMode.HTML)
            return

        # Execute safe shell command
        await _execute_and_stream(app, chat, user, message, shell_command=command_input)


async def _prompt_dangerous_confirmation(
    app: BotApplication,
    chat: Any,
    user: Any,
    message: Any,
    shell_command: str,
) -> None:
    """Prompt user with inline confirmation buttons for dangerous command."""
    pending = app.confirmation_manager.create_confirmation(
        user_id=user.id,
        chat_id=chat.id,
        command_text=shell_command,
    )

    keyboard = [
        [
            InlineKeyboardButton(messages.BTN_CONFIRM_EXECUTION, callback_data=f"confirm:{pending.nonce}"),
            InlineKeyboardButton(messages.BTN_CANCEL_EXECUTION, callback_data=f"cancel:{pending.nonce}"),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    sent = await chat.send_message(
        messages.MSG_DANGEROUS_CONFIRMATION_PROMPT.format(command=shell_command),
        parse_mode=ParseMode.HTML,
        reply_markup=reply_markup,
    )
    app.confirmation_manager.set_message_id(pending.nonce, sent.message_id)

    # Log audit and alert admin
    event = AuditEvent(
        user_id=user.id,
        chat_id=chat.id,
        message_id=message.message_id,
        event_type="command_request",
        command=shell_command,
        decision="confirmation_required",
        reason="dangerous_pattern_match",
    )
    alert = f"⚠️ <b>CẢNH BÁO:</b> Quản trị viên <code>{user.id}</code> vừa kích hoạt yêu cầu xác nhận lệnh nguy hiểm: <code>{shell_command}</code>"
    await app.audit_logger.log_and_alert(event, alert_message=alert)


async def _prompt_sudo_confirmation(
    app: BotApplication,
    chat: Any,
    user: Any,
    message: Any,
    argv: list[str] | None = None,
    shell_command: str | None = None,
) -> None:
    """Prompt user with inline confirmation buttons for sudo elevation."""
    cmd_text = shell_command if shell_command else " ".join(argv or [])
    pending = app.confirmation_manager.create_confirmation(
        user_id=user.id,
        chat_id=chat.id,
        command_text=cmd_text,
    )

    keyboard = [
        [
            InlineKeyboardButton(messages.BTN_SUDO_ACCEPT, callback_data=f"sudo_accept:{pending.nonce}"),
            InlineKeyboardButton(messages.BTN_SUDO_REJECT, callback_data=f"sudo_reject:{pending.nonce}"),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    sent = await chat.send_message(
        messages.MSG_SUDO_CONFIRMATION_PROMPT.format(command=cmd_text),
        parse_mode=ParseMode.HTML,
        reply_markup=reply_markup,
    )
    app.confirmation_manager.set_message_id(pending.nonce, sent.message_id)


async def confirmation_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle callback queries from confirmation dialogs."""
    app: BotApplication = context.application.bot_data["app_state"]
    query = update.callback_query
    if not query or not query.data:
        return

    await query.answer()
    data = query.data
    user = query.from_user
    cb_msg = query.message
    chat = cb_msg.chat if cb_msg else None

    if not chat or not user:
        return

    # Format: action:nonce
    parts = data.split(":", 1)
    if len(parts) != 2:
        return

    action, nonce = parts

    # 1. Cancel actions
    if action in ("cancel", "sudo_reject"):
        app.confirmation_manager.cancel(nonce)
        try:
            await query.edit_message_reply_markup(reply_markup=None)
            await query.edit_message_text(
                messages.MSG_CONFIRMATION_CANCELLED if action == "cancel" else messages.MSG_SUDO_REJECTED,
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
        return

    # 2. Confirm actions
    if action in ("confirm", "sudo_accept"):
        success, reason, pending = app.confirmation_manager.verify_and_consume(
            nonce=nonce,
            user_id=user.id,
            chat_id=chat.id,
            message_id=cb_msg.message_id if cb_msg else None,
        )

        if not success or not pending:
            try:
                await query.edit_message_reply_markup(reply_markup=None)
                await query.edit_message_text(messages.MSG_CONFIRMATION_INVALID, parse_mode=ParseMode.HTML)
            except Exception:
                pass
            return

        try:
            await query.edit_message_reply_markup(reply_markup=None)
            await query.edit_message_text(
                f"✅ <b>Đã xác nhận thực thi:</b> <code>{pending.command_text}</code>",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass

        use_sudo = (action == "sudo_accept")
        await _execute_and_stream(
            app,
            chat,
            user,
            cb_msg,
            shell_command=pending.command_text,
            use_sudo=use_sudo,
        )


async def _execute_and_stream(
    app: BotApplication,
    chat: Any,
    user: Any,
    message: Any,
    argv: list[str] | None = None,
    shell_command: str | None = None,
    use_sudo: bool = False,
) -> None:
    """Execute process, track job in terminal session, and paginate output across Telegram messages."""
    terminal_gw = app.get_or_create_terminal_gateway(user.id)
    terminal = terminal_gw.get_active_terminal()
    terminal.stop_requested = False
    terminal.state = TerminalState.RUNNING

    display_cmd = shell_command if shell_command else " ".join(argv or [])
    job = app.job_manager.register_job(user_id=user.id, command_display=display_cmd)
    terminal.current_job_id = job.job_id

    try:
        # Execute via Native Bridge (C native engine if available, else ProcessExecutor)
        result = await app.native_bridge.execute(
            argv=argv,
            shell_command=shell_command,
            use_sudo=use_sudo,
            timeout_seconds=app.config.limits.command_default_timeout_seconds,
            work_dir=terminal.cwd,
        )

        # Sanitize and paginate output
        raw_combined = result.combined_output
        clean_text = sanitize_output(raw_combined)

        chunks = paginate_output(clean_text)

        # Send chunks sequentially, respecting .stop requests
        for chunk in chunks:
            if terminal.stop_requested:
                await chat.send_message(messages.MSG_COMMAND_STOPPED, parse_mode=ParseMode.HTML)
                break
            await chat.send_message(chunk, parse_mode=ParseMode.HTML)
            # Gentle yield to prevent hitting Telegram rate limits
            await asyncio.sleep(0.1)

        # Log audit
        event = AuditEvent(
            user_id=user.id,
            chat_id=chat.id,
            message_id=message.message_id if message else None,
            event_type="command_executed",
            command=display_cmd,
            decision="allowed",
            reason="ok" if not result.is_timeout else "timeout",
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            output_size_bytes=len(raw_combined),
        )
        app.audit_logger.log(event)

    except Exception as exc:
        await chat.send_message(f"❌ <b>Lỗi khi thực thi:</b> {exc}", parse_mode=ParseMode.HTML)
    finally:
        terminal.state = TerminalState.IDLE
        terminal.current_job_id = None
        app.job_manager.unregister_job(job.job_id)
