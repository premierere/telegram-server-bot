#!/usr/bin/env python3
"""Offline TOTP Provisioning Tool.

Generates a cryptographically strong RFC 6238 Base32 secret for an authorized
Telegram user ID on the server, saves it to a protected file (0600 permissions),
and displays the otpauth:// URI for importing into authenticator apps.

Usage:
    python scripts/setup_totp.py <USER_ID> [--totp-dir DIR]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import pyotp


def setup_totp(user_id: int, totp_dir: Path) -> str:
    """Generate and store TOTP secret for user_id with 0600 permissions."""
    totp_dir.mkdir(parents=True, exist_ok=True)
    secret_path = totp_dir / f"{user_id}.secret"

    # Generate cryptographically secure base32 secret (160-bit default in pyotp)
    secret = pyotp.random_base32()

    # Write secret atomically or with strict permissions
    secret_path.write_text(secret.strip(), encoding="utf-8")

    # Enforce strict 0600 permissions on POSIX systems
    if os.name == "posix":
        os.chmod(secret_path, 0o600)

    return secret


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Khởi tạo mã bí mật TOTP 2FA cho quản trị viên Telegram (Offline Setup)."
    )
    parser.add_argument(
        "user_id",
        type=int,
        help="Numeric Telegram User ID của quản trị viên (ví dụ: 123456789).",
    )
    parser.add_argument(
        "--totp-dir",
        type=Path,
        default=Path("/var/lib/telegram-server-bot/totp"),
        help="Thư mục lưu trữ khóa TOTP trên server (mặc định: /var/lib/telegram-server-bot/totp).",
    )
    parser.add_argument(
        "--issuer",
        type=str,
        default="TelegramServerBot",
        help="Tên Issuer hiển thị trên ứng dụng xác thực (mặc định: TelegramServerBot).",
    )

    args = parser.parse_args()

    try:
        secret = setup_totp(args.user_id, args.totp_dir)
    except Exception as exc:
        print(f"[!] Lỗi khi thiết lập mã bí mật TOTP: {exc}", file=sys.stderr)
        return 1

    totp = pyotp.TOTP(secret)
    otpauth_uri = totp.provisioning_uri(
        name=str(args.user_id),
        issuer_name=args.issuer,
    )

    print("=" * 64)
    print("  KHỞI TẠO XÁC THỰC HAI BƯỚC (TOTP 2FA) THÀNH CÔNG")
    print("=" * 64)
    print(f"Telegram User ID: {args.user_id}")
    print(f"File lưu trữ:     {args.totp_dir / f'{args.user_id}.secret'}")
    print(f"Mã bí mật Base32: {secret}")
    print("-" * 64)
    print("URI nhập ứng dụng (Google Authenticator / Aegis / Bitwarden / 1Password):")
    print(otpauth_uri)
    print("-" * 64)
    print("LƯU Ý BẢO MẬT:")
    print("1. Mã bí mật này KHÔNG ĐƯỢC gửi qua Telegram hay bất kỳ kênh chat nào.")
    print("2. Quét hoặc nhập URI trên trực tiếp trên server console an toàn.")
    print("3. File bí mật đã được phân quyền 0600 (chỉ user dịch vụ có quyền đọc).")
    print("=" * 64)

    return 0


if __name__ == "__main__":
    sys.exit(main())
