"""System commands and interactive terminal gateway dot-command handlers."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from src import messages
from src.audit import AuditEvent
from src.executor.terminals import parse_dot_command

if TYPE_CHECKING:
    from src.bot import BotApplication


async def status_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /status: run built-in safe status commands."""
    app: BotApplication = context.application.bot_data["app_state"]
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return

    session = app.session_manager.get_session(user.id)
    if not session:
        await chat.send_message(messages.MSG_NOT_LOGGED_IN, parse_mode=ParseMode.HTML)
        return
    session.touch()

    # Run system status
    cmd = "uptime" if app.config.users[user.id].mode == "restricted" else "uptime && free -m && df -h /"
    result = await app.native_bridge.execute(
        shell_command=cmd if app.config.users[user.id].mode != "restricted" else None,
        argv=["uptime"] if app.config.users[user.id].mode == "restricted" else None,
        timeout_seconds=10.0,
    )

    clean = result.combined_output.decode("utf-8", errors="replace")
    await chat.send_message(
        f"{messages.MSG_STATUS_HEADER}<pre><code class='language-text'>{clean}</code></pre>",
        parse_mode=ParseMode.HTML,
    )


async def whoami_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /whoami: display user info, session state, and active terminal."""
    app: BotApplication = context.application.bot_data["app_state"]
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return

    user_cfg = app.config.users.get(user.id)
    mode = user_cfg.mode if user_cfg else "restricted"

    session = app.session_manager.get_session(user.id)
    if session:
        session_status = "Đang hoạt động (Active)"
        remaining_sec = max(
            0,
            int(
                min(
                    session.idle_timeout_seconds - (time.time() - session.last_activity_time),
                    session.absolute_timeout_seconds - (time.time() - session.login_time),
                )
            ),
        )
        remaining_time = f"{remaining_sec // 60}m {remaining_sec % 60}s"
    else:
        session_status = "Chưa đăng nhập (Logged out)"
        remaining_time = "N/A"

    gw = app.get_or_create_terminal_gateway(user.id)

    text = messages.MSG_WHOAMI.format(
        user_id=user.id,
        mode=mode.upper(),
        session_status=session_status,
        remaining_time=remaining_time,
        active_terminal=gw.active_terminal_id,
    )
    await chat.send_message(text, parse_mode=ParseMode.HTML)


async def jobs_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /jobs: list active running jobs."""
    app: BotApplication = context.application.bot_data["app_state"]
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return

    session = app.session_manager.get_session(user.id)
    if not session:
        await chat.send_message(messages.MSG_NOT_LOGGED_IN, parse_mode=ParseMode.HTML)
        return
    session.touch()

    jobs = app.job_manager.list_jobs()
    if not jobs:
        await chat.send_message("ℹ️ Hiện tại không có tác vụ nào đang chạy.", parse_mode=ParseMode.HTML)
        return

    lines = ["📋 <b>CÁC TÁC VỤ ĐANG CHẠY:</b>\n"]
    for j in jobs:
        lines.append(
            f"• <code>{j.job_id}</code> | PID: <code>{j.pid or 'N/A'}</code> | "
            f"User: <code>{j.user_id}</code> | Chạy: <b>{int(j.elapsed_seconds)}s</b>\n"
            f"  Lệnh: <code>{j.command_display}</code>"
        )
    await chat.send_message("\n".join(lines), parse_mode=ParseMode.HTML)


async def kill_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /kill JOB_ID."""
    app: BotApplication = context.application.bot_data["app_state"]
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return

    session = app.session_manager.get_session(user.id)
    if not session:
        await chat.send_message(messages.MSG_NOT_LOGGED_IN, parse_mode=ParseMode.HTML)
        return
    session.touch()

    args = context.args or []
    if not args:
        await chat.send_message(messages.MSG_KILL_USAGE, parse_mode=ParseMode.HTML)
        return

    job_id = args[0].strip()
    success, reason = await app.job_manager.kill_job(job_id)

    if success:
        await chat.send_message(messages.MSG_KILL_SUCCESS.format(job_id=job_id), parse_mode=ParseMode.HTML)
    else:
        await chat.send_message(messages.MSG_KILL_FAILED.format(job_id=job_id), parse_mode=ParseMode.HTML)


async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /help: show usage and authorized restricted commands."""
    app: BotApplication = context.application.bot_data["app_state"]
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return

    user_cfg = app.config.users.get(user.id)
    mode = user_cfg.mode if user_cfg else "restricted"

    body = messages.MSG_HELP_HEADER.format(mode=mode.upper())

    if mode == "restricted":
        body += "\n<b>Các lệnh được phép trong policy.yaml:</b>\n"
        for name, entry in app.policy_engine.commands.items():
            params_desc = ", ".join(entry.params.keys()) if entry.params else "không tham số"
            body += f"• <code>/run {name}</code> ({params_desc})\n  <i>{entry.description}</i>\n"

    await chat.send_message(body, parse_mode=ParseMode.HTML)


async def dot_command_dispatcher(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Intercept and handle dot commands (.stop, .new, .t1..10, .terminals, .close)."""
    app: BotApplication = context.application.bot_data["app_state"]
    message = update.effective_message
    user = update.effective_user
    chat = update.effective_chat

    if not message or not user or not chat or not message.text:
        return

    parsed = parse_dot_command(message.text)
    if not parsed:
        return

    session = app.session_manager.get_session(user.id)
    if not session:
        await chat.send_message(messages.MSG_NOT_LOGGED_IN, parse_mode=ParseMode.HTML)
        return
    session.touch()

    cmd_type, args = parsed
    gw = app.get_or_create_terminal_gateway(user.id)

    # 1. Stop command (.stop)
    if cmd_type == "stop":
        active_t = gw.get_active_terminal()
        active_t.request_stop()
        await chat.send_message(
            messages.MSG_TERMINAL_STOPPED.format(tid=active_t.terminal_id),
            parse_mode=ParseMode.HTML,
        )
        return

    # 2. New terminal (.new, .n)
    if cmd_type == "new":
        success, new_id, msg = gw.open_new_terminal()
        await chat.send_message(msg, parse_mode=ParseMode.HTML)
        return

    # 3. Switch terminal (.t1 .. .t10)
    if cmd_type == "switch" and args:
        try:
            target_id = int(args[0])
            success, msg = gw.switch_terminal(target_id)
            await chat.send_message(msg, parse_mode=ParseMode.HTML)
        except ValueError:
            await chat.send_message("❌ ID terminal không hợp lệ.", parse_mode=ParseMode.HTML)
        return

    # 4. List terminals (.terminals, .list)
    if cmd_type == "list":
        terminals_list = gw.list_terminals()
        lines = [messages.MSG_TERMINAL_LIST_HEADER]
        for t in terminals_list:
            mark = " 👈 <i>(đang chọn)</i>" if t["is_active"] else ""
            lines.append(
                f"• <b>Terminal #{t['id']}</b>: <code>{t['state']}</code>{mark}"
            )
        await chat.send_message("\n".join(lines), parse_mode=ParseMode.HTML)
        return

    # 5. Close terminal (.close)
    if cmd_type == "close":
        target = int(args[0]) if args and args[0].isdigit() else None
        success, msg = gw.close_terminal(target)
        await chat.send_message(msg, parse_mode=ParseMode.HTML)
        return
