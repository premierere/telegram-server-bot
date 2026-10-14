"""Tests for TOTP second-factor authentication, replay prevention, and lockout."""

from pathlib import Path

import pyotp
import pytest

from src.auth.totp import TOTPManager


@pytest.fixture
def secret_key() -> str:
    return pyotp.random_base32()


@pytest.fixture
def totp_dir(tmp_path: Path, secret_key: str) -> Path:
    d = tmp_path / "totp"
    d.mkdir()
    (d / "1001.secret").write_text(secret_key, encoding="utf-8")
    return d


def test_valid_totp_verification(totp_dir: Path, secret_key: str):
    manager = TOTPManager(totp_dir=totp_dir, enforce_file_perms=False)
    totp = pyotp.TOTP(secret_key)
    code = totp.now()

    is_valid, reason = manager.verify_code(user_id=1001, code=code)
    assert is_valid is True
    assert reason == "ok"


def test_clock_drift_window(totp_dir: Path, secret_key: str):
    manager = TOTPManager(totp_dir=totp_dir, max_drift_steps=1, enforce_file_perms=False)
    totp = pyotp.TOTP(secret_key)

    base_time = 100000.0
    code_at_base = totp.at(int(base_time))

    # Same time: passes
    is_valid, _ = manager.verify_code(user_id=1001, code=code_at_base, current_time=base_time)
    assert is_valid is True

    # Code generated 30s ago (1 step drift): passes
    code_prev = totp.at(int(base_time + 100.0) - 30)
    is_valid_drift, _ = manager.verify_code(user_id=1001, code=code_prev, current_time=base_time + 100.0)
    assert is_valid_drift is True

    # Code generated 90s ago (3 steps drift): fails
    code_old = totp.at(int(base_time + 300.0) - 90)
    is_valid_far, reason = manager.verify_code(user_id=1001, code=code_old, current_time=base_time + 300.0)
    assert is_valid_far is False
    assert reason == "invalid_code"


def test_replay_code_rejected(totp_dir: Path, secret_key: str):
    manager = TOTPManager(totp_dir=totp_dir, enforce_file_perms=False)
    totp = pyotp.TOTP(secret_key)
    code = totp.at(100000)

    # First use: passes
    is_valid, reason = manager.verify_code(user_id=1001, code=code, current_time=100000.0)
    assert is_valid is True
    assert reason == "ok"

    # Replay attempt: rejected
    is_valid_replay, reason_replay = manager.verify_code(user_id=1001, code=code, current_time=100005.0)
    assert is_valid_replay is False
    assert reason_replay == "code_already_used"


def test_five_failures_trigger_lockout_with_backoff(totp_dir: Path):
    manager = TOTPManager(totp_dir=totp_dir, lockout_threshold=5, base_lockout_seconds=300.0, enforce_file_perms=False)

    # 4 consecutive invalid codes
    for i in range(4):
        is_valid, reason = manager.verify_code(user_id=1001, code="000000", current_time=1000.0 + i)
        assert is_valid is False
        assert reason == "invalid_code"

    # 5th invalid code: triggers lockout
    is_valid, reason = manager.verify_code(user_id=1001, code="000000", current_time=1005.0)
    assert is_valid is False
    assert reason.startswith("account_locked")

    # 6th attempt while locked: rejected immediately
    is_valid, reason = manager.verify_code(user_id=1001, code="123456", current_time=1010.0)
    assert is_valid is False
    assert reason.startswith("account_locked")


def test_invalid_format_rejected(totp_dir: Path):
    manager = TOTPManager(totp_dir=totp_dir, enforce_file_perms=False)

    assert manager.verify_code(1001, "abc")[1] == "invalid_format"
    assert manager.verify_code(1001, "12345")[1] == "invalid_format"
    assert manager.verify_code(1001, "1234567")[1] == "invalid_format"
    assert manager.verify_code(1001, "123 45")[1] == "invalid_format"
