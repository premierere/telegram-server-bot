"""Tests for scripts/setup_totp.py provisioning tool."""

from pathlib import Path

import pyotp

from scripts.setup_totp import setup_totp


def test_setup_totp_creates_valid_secret(tmp_path: Path):
    user_id = 987654321
    totp_dir = tmp_path / "totp"

    secret = setup_totp(user_id, totp_dir)
    assert len(secret) == 32
    # Verify it can be decoded as base32
    totp = pyotp.TOTP(secret)
    code = totp.now()
    assert len(code) == 6
    assert code.isdigit()

    # Verify file saved
    secret_file = totp_dir / f"{user_id}.secret"
    assert secret_file.exists()
    assert secret_file.read_text(encoding="utf-8").strip() == secret
