"""CLI entrypoint for Telegram Linux Server Administration Bot.

Supports running via:
    python -m src.main [--config PATH]
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from src.bot import BotApplication
from src.config import SecurityError, check_root_user, load_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("telegram-server-bot")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Production-Grade Telegram Server Administration Bot"
    )
    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default=Path("config.yaml"),
        help="Đường dẫn tới tệp cấu hình YAML (mặc định: config.yaml)",
    )
    args = parser.parse_args()

    # 1. Refuse to run as root
    try:
        check_root_user()
    except SecurityError as exc:
        logger.critical(str(exc))
        return 1

    # 2. Load and validate configuration fail-closed
    try:
        config = load_config(args.config)
    except Exception as exc:
        logger.critical(f"Không thể nạp tệp cấu hình '{args.config}': {exc}")
        return 1

    # 3. Assemble and run bot application
    try:
        app = BotApplication(config)
        logger.info(f"Đang khởi động bot cho các quản trị viên: {config.allowed_user_ids}")
        app.run_polling()
    except Exception as exc:
        logger.critical(f"Lỗi nghiêm trọng trong quá trình vận hành bot: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
