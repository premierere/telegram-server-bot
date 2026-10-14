"""Global error handler for unexpected exceptions. Fails closed safely."""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

if TYPE_CHECKING:
    from src.bot import BotApplication

logger = logging.getLogger(__name__)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle uncaught errors across the application."""
    exc = context.error
    logger.error("Exception occurred while handling an update: %s", exc, exc_info=exc)

    # Output to stderr
    sys.stderr.write(f"[ERROR] Uncaught exception: {exc}\n")

    if isinstance(update, Update) and update.effective_chat:
        try:
            await update.effective_chat.send_message(
                "❌ <b>Đã xảy ra lỗi nội bộ trong hệ thống.</b> Lệnh đã bị hủy bỏ để đảm bảo an toàn.",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
