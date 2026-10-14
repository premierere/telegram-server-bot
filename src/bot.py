"""Main bot application assembly and lifecycle management.

Configures:
- Long polling over outbound HTTPS.
- drop_pending_updates=True at startup.
- allowed_updates=["message", "callback_query"].
- Identity filter gatekeeper running at group -1 (drops unauthorized/stale updates before handlers).
- Registration of command handlers, dot commands, confirmation callbacks, and error handler.
"""

from __future__ import annotations

import logging
from pathlib import Path

from telegram import Update
from telegram.ext import (
    Application,
    ApplicationHandlerStop,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    TypeHandler,
    filters,
)

from src.audit import AuditEvent, AuditLogger
from src.auth.confirmation import ConfirmationManager
from src.auth.pam_verifier import LinuxPAMVerifier
from src.auth.session import SessionManager
from src.auth.state import AuthStateManager
from src.auth.totp import TOTPManager
from src.config import Config
from src.executor.jobs import JobManager
from src.executor.native_bridge import NativeExecutionBridge
from src.executor.pty_session import PTYSessionManager
from src.executor.terminals import TerminalGateway
from src.handlers.auth import exit_handler, login_handler, logout_handler
from src.handlers.command import confirmation_callback_handler, direct_text_dispatcher, run_handler
from src.handlers.error import error_handler
from src.handlers.system import (
    close_handler,
    help_handler,
    jobs_handler,
    kill_handler,
    new_terminal_handler,
    status_handler,
    stop_handler,
    switch_terminal_handler,
    terminals_handler,
    whoami_handler,
)
from src.identity import IdentityFilter
from src.policy import PolicyEngine

logger = logging.getLogger(__name__)


class BotApplication:
    """Encapsulates the state and lifecycle of the Telegram Server Administration Bot."""

    def __init__(self, config: Config) -> None:
        self.config = config

        # 1. Audit logger and admin alerts
        self.audit_logger = AuditLogger(
            audit_file_path=self.config.audit_file,
            admin_user_ids=self.config.admin_user_ids,
            admin_notifier=self._send_admin_alert,
        )

        # 2. Identity and replay filter
        self.identity_filter = IdentityFilter(
            allowed_user_ids=self.config.allowed_user_ids,
            max_message_age_seconds=self.config.limits.message_max_age_seconds,
            audit_logger=self.audit_logger.log,
        )

        # 3. Authentication & Sessions
        self.totp_manager = TOTPManager(
            totp_dir=self.config.totp_dir,
            max_drift_steps=self.config.limits.totp_max_clock_drift_steps,
            lockout_threshold=self.config.limits.totp_lockout_threshold,
        )
        self.session_manager = SessionManager(
            idle_timeout_seconds=self.config.limits.session_idle_timeout_seconds,
            absolute_timeout_seconds=self.config.limits.session_absolute_timeout_seconds,
        )
        self.auth_state_manager = AuthStateManager()
        self.pam_verifier = LinuxPAMVerifier()
        self.confirmation_manager = ConfirmationManager(
            default_expiry_seconds=self.config.limits.confirmation_timeout_seconds
        )

        # 4. Policy Engine
        self.policy_engine = PolicyEngine(policy_path=self.config.policy_file)

        # 5. Execution & Jobs
        self.job_manager = JobManager(
            max_concurrent_jobs=self.config.limits.max_concurrent_jobs,
            rate_limit_commands_per_minute=self.config.limits.rate_limit_commands_per_minute,
        )
        self.native_bridge = NativeExecutionBridge()
        self.pty_session_manager = PTYSessionManager()

        # 6. Multi-terminal gateways per user
        self.terminal_gateways: dict[int, TerminalGateway] = {}

        # 7. Telegram Application
        self.tg_app: Application | None = None

    def get_or_create_terminal_gateway(self, user_id: int) -> TerminalGateway:
        """Get or create terminal gateway for user."""
        if user_id not in self.terminal_gateways:
            self.terminal_gateways[user_id] = TerminalGateway(
                user_id=user_id,
                default_work_dir=Path(self.config.work_dir),
            )
        return self.terminal_gateways[user_id]

    async def _send_admin_alert(self, admin_id: int, message: str) -> None:
        """Send urgent notification to administrator."""
        if self.tg_app and self.tg_app.bot:
            await self.tg_app.bot.send_message(
                chat_id=admin_id,
                text=message,
                parse_mode="HTML",
            )

    def build_application(self) -> Application:
        """Configure Telegram Application, middleware, and handlers."""
        app = Application.builder().token(self.config.bot_token).build()
        self.tg_app = app
        app.bot_data["app_state"] = self

        # Gatekeeper Middleware (group -1): stops unauthorized/stale updates before handlers
        async def gatekeeper_middleware(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            is_valid, reason = self.identity_filter.validate_update(update)
            if not is_valid:
                raise ApplicationHandlerStop()

        app.add_handler(TypeHandler(Update, gatekeeper_middleware), group=-1)

        # Command handlers
        app.add_handler(CommandHandler("login", login_handler))
        app.add_handler(CommandHandler("logout", logout_handler))
        app.add_handler(CommandHandler("exit", exit_handler))
        app.add_handler(CommandHandler("stop", stop_handler))
        app.add_handler(CommandHandler(["new", "newterminal", "n"], new_terminal_handler))
        app.add_handler(CommandHandler(["terminals", "list"], terminals_handler))
        app.add_handler(CommandHandler("close", close_handler))
        app.add_handler(CommandHandler("terminal", switch_terminal_handler))

        # Register /t1 .. /t10
        def _make_switch(num: int):
            async def handler(u: Update, c: ContextTypes.DEFAULT_TYPE) -> None:
                await switch_terminal_handler(u, c, terminal_num=num)
            return handler

        for i in range(1, 11):
            app.add_handler(CommandHandler(f"t{i}", _make_switch(i)))

        app.add_handler(CommandHandler("run", run_handler))
        app.add_handler(CommandHandler("status", status_handler))
        app.add_handler(CommandHandler("whoami", whoami_handler))
        app.add_handler(CommandHandler("jobs", jobs_handler))
        app.add_handler(CommandHandler("kill", kill_handler))
        app.add_handler(CommandHandler("help", help_handler))

        # Confirmation callback queries
        app.add_handler(CallbackQueryHandler(confirmation_callback_handler))

        # Direct interactive text & command execution (without /run prefix)
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, direct_text_dispatcher))

        # Error handler
        app.add_error_handler(error_handler)

        return app

    def run_polling(self) -> None:
        """Start long-polling with fail-closed startup parameters."""
        app = self.build_application()

        # Log service start
        event = AuditEvent(
            user_id=0,
            event_type="service_started",
            decision="allowed",
            reason="startup",
        )
        self.audit_logger.log(event)

        logger.info("Starting Telegram Bot with drop_pending_updates=True...")
        app.run_polling(
            drop_pending_updates=True,
            allowed_updates=["message", "callback_query"],
        )
