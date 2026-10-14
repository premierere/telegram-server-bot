"""System commands and interactive terminal gateway dot-command handlers."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from src import messages

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


async def stop_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /stop: send SIGINT (Ctrl+C) to active terminal process."""
    app: BotApplication = context.application.bot_data["app_state"]
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return

    term = app.pty_session_manager.get_active_terminal(user.id)
    if term:
        term.stop_requested = True
    await chat.send_message(
        "🛑 <b>Đã gửi tín hiệu ngắt (Ctrl+C) tới tiến trình đang chạy.</b>",
        parse_mode=ParseMode.HTML,
    )


async def new_terminal_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /new [username]: open new terminal for current user or prompt password for target user."""
    app: BotApplication = context.application.bot_data["app_state"]
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return

    from src.auth.state import AuthStage

    args = context.args or []
    if args:
        target_user = args[0].strip()
        app.auth_state_manager.set_stage(
            user.id,
            AuthStage.AWAITING_NEW_TERMINAL_PASSWORD,
            target_new_terminal_username=target_user,
        )
        await chat.send_message(
            f"🔑 Vui lòng nhập mật khẩu cho tài khoản <code>{target_user}</code> để tạo terminal mới (tin nhắn sẽ được xóa ngay):",
            parse_mode=ParseMode.HTML,
        )
        return

    # No args: open terminal for current active user
    active_user = app.auth_state_manager.get_active_username(user.id) or "root"
    try:
        term = await app.pty_session_manager.create_terminal(user.id, active_user)
        banner = app.pty_session_manager.format_terminal_prompt(user.id, term.terminal_id)
        await chat.send_message(
            f"<pre><code class='language-text'>{banner}</code></pre>",
            parse_mode=ParseMode.HTML,
        )
    except ValueError as exc:
        await chat.send_message(f"❌ {exc}", parse_mode=ParseMode.HTML)


async def switch_terminal_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    terminal_num: int | None = None,
) -> None:
    """Handle /t1..10 or /terminal <N>: switch active terminal."""
    app: BotApplication = context.application.bot_data["app_state"]
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return

    target_id = terminal_num
    if target_id is None:
        args = context.args or []
        if args and args[0].isdigit():
            target_id = int(args[0])
        else:
            await chat.send_message("❌ Vui lòng chỉ định số terminal (ví dụ: /t1, /t2 hoặc /terminal 1).", parse_mode=ParseMode.HTML)
            return

    switched, msg = app.pty_session_manager.switch_terminal(user.id, target_id)
    if not switched:
        await chat.send_message(f"❌ {msg}", parse_mode=ParseMode.HTML)
        return

    banner = app.pty_session_manager.format_terminal_prompt(user.id, target_id)
    await chat.send_message(
        f"<pre><code class='language-text'>{banner}</code></pre>",
        parse_mode=ParseMode.HTML,
    )


async def terminals_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /terminals: list all active terminals for user."""
    app: BotApplication = context.application.bot_data["app_state"]
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return

    terms = app.pty_session_manager.list_terminals(user.id)
    if not terms:
        await chat.send_message("❌ Chưa có terminal nào đang mở. Sử dụng <code>/new</code> để mở terminal mới.", parse_mode=ParseMode.HTML)
        return

    active_term = app.pty_session_manager.get_active_terminal(user.id)
    lines = ["🖥️ <b>Danh sách Terminal đang hoạt động:</b>\n"]
    for t in terms:
        is_active = (active_term and active_term.terminal_id == t.terminal_id)
        mark = " 👈 <i>(đang kích hoạt)</i>" if is_active else ""
        time_str = t.login_time.strftime("%d/%m/%Y %H:%M:%S")
        lines.append(
            f"• <b>Terminal #{t.terminal_id}</b> [<code>{t.username}</code>] - đăng nhập: <code>{time_str}</code>{mark}"
        )

    await chat.send_message("\n".join(lines), parse_mode=ParseMode.HTML)


async def close_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /close [N]: close active or specified terminal."""
    app: BotApplication = context.application.bot_data["app_state"]
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return

    args = context.args or []
    target_id = int(args[0]) if (args and args[0].isdigit()) else None

    success, msg = await app.pty_session_manager.close_terminal(user.id, target_id)
    prefix = "✅" if success else "❌"
    await chat.send_message(f"{prefix} {msg}", parse_mode=ParseMode.HTML)
