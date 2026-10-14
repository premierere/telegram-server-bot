"""Tests for configuration loading, validation, and security checks."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from src.config import (
    Config,
    ConfigurationError,
    SecurityError,
    check_file_permissions,
    check_root_user,
    load_config,
    resolve_bot_token,
)


@pytest.fixture
def valid_config_dict() -> dict:
    return {
        "allowed_user_ids": [10001, 10002],
        "admin_user_ids": [10001],
        "users": {
            10001: {"mode": "shell"},
            10002: {"mode": "restricted"},
        },
        "bot_token_file": None,
        "totp_dir": "/tmp/totp",
        "policy_file": "policy.yaml",
        "audit_file": "/tmp/audit.jsonl",
        "work_dir": "/tmp/sandbox",
        "limits": {
            "session_idle_timeout_seconds": 600,
            "session_absolute_timeout_seconds": 3600,
            "command_default_timeout_seconds": 30,
            "command_max_timeout_seconds": 300,
            "max_concurrent_jobs": 2,
            "rate_limit_commands_per_minute": 10,
        },
    }


@pytest.fixture
def config_file(tmp_path: Path, valid_config_dict: dict) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.dump(valid_config_dict), encoding="utf-8")
    return p


def test_valid_config_loads(config_file: Path):
    cfg = load_config(
        config_file,
        enforce_file_perms=False,
        override_token="123456789:ABCDEF_mock_token_for_testing_purposes",
    )
    assert isinstance(cfg, Config)
    assert cfg.allowed_user_ids == [10001, 10002]
    assert cfg.admin_user_ids == [10001]
    assert cfg.users[10001].mode == "shell"
    assert cfg.users[10002].mode == "restricted"
    assert cfg.limits.session_idle_timeout_seconds == 600
    assert cfg.limits.max_concurrent_jobs == 2
    assert cfg.bot_token == "123456789:ABCDEF_mock_token_for_testing_purposes"


def test_missing_config_file(tmp_path: Path):
    with pytest.raises(ConfigurationError, match="Configuration file not found"):
        load_config(tmp_path / "non_existent.yaml", enforce_file_perms=False)


def test_unknown_root_key_fails(tmp_path: Path, valid_config_dict: dict):
    valid_config_dict["malicious_or_unknown_key"] = True
    p = tmp_path / "bad_config.yaml"
    p.write_text(yaml.dump(valid_config_dict), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="Unknown configuration key"):
        load_config(p, enforce_file_perms=False, override_token="token")


def test_unknown_limit_key_fails(tmp_path: Path, valid_config_dict: dict):
    valid_config_dict["limits"]["unknown_limit"] = 123
    p = tmp_path / "bad_config.yaml"
    p.write_text(yaml.dump(valid_config_dict), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="Unknown limit setting"):
        load_config(p, enforce_file_perms=False, override_token="token")


def test_empty_allowed_user_ids_fails(tmp_path: Path, valid_config_dict: dict):
    valid_config_dict["allowed_user_ids"] = []
    p = tmp_path / "bad_config.yaml"
    p.write_text(yaml.dump(valid_config_dict), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="non-empty list of numeric user IDs"):
        load_config(p, enforce_file_perms=False, override_token="token")


def test_invalid_user_id_types_fail(tmp_path: Path, valid_config_dict: dict):
    valid_config_dict["allowed_user_ids"] = ["username_not_allowed"]
    p = tmp_path / "bad_config.yaml"
    p.write_text(yaml.dump(valid_config_dict), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="must be an integer"):
        load_config(p, enforce_file_perms=False, override_token="token")


def test_invalid_user_mode_fails(tmp_path: Path, valid_config_dict: dict):
    valid_config_dict["users"][10001]["mode"] = "unrestricted_root"
    p = tmp_path / "bad_config.yaml"
    p.write_text(yaml.dump(valid_config_dict), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="Invalid mode"):
        load_config(p, enforce_file_perms=False, override_token="token")


def test_invalid_timeout_order_fails(tmp_path: Path, valid_config_dict: dict):
    valid_config_dict["limits"]["command_default_timeout_seconds"] = 400
    valid_config_dict["limits"]["command_max_timeout_seconds"] = 300
    p = tmp_path / "bad_config.yaml"
    p.write_text(yaml.dump(valid_config_dict), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="cannot exceed command_max_timeout_seconds"):
        load_config(p, enforce_file_perms=False, override_token="token")


def test_root_user_execution_rejected():
    with patch("os.geteuid", return_value=0, create=True):
        with pytest.raises(SecurityError, match="Running as root is strictly forbidden"):
            check_root_user()


def test_token_resolution_order(tmp_path: Path):
    creds_dir = tmp_path / "systemd_creds"
    creds_dir.mkdir()
    cred_token_file = creds_dir / "bot_token"
    cred_token_file.write_text("systemd_cred_token_123", encoding="utf-8")

    file_token_file = tmp_path / "file_token.txt"
    file_token_file.write_text("file_token_456", encoding="utf-8")

    # 1. Systemd Credential takes first precedence
    with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(creds_dir), "TELEGRAM_BOT_TOKEN": "env_token_789"}):
        token = resolve_bot_token(bot_token_file=str(file_token_file), enforce_file_perms=False)
        assert token == "systemd_cred_token_123"

    # 2. File takes precedence if credential not present
    with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "env_token_789"}, clear=True):
        token = resolve_bot_token(bot_token_file=str(file_token_file), enforce_file_perms=False)
        assert token == "file_token_456"

    # 3. Environment variable used if no credential or file
    with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "env_token_789"}, clear=True):
        token = resolve_bot_token(bot_token_file=None, enforce_file_perms=False)
        assert token == "env_token_789"

    # 4. Error if none available
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ConfigurationError, match="No Telegram bot token found"):
            resolve_bot_token(bot_token_file=None, enforce_file_perms=False)


def test_insecure_file_permissions_on_posix(tmp_path: Path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("secret_content")

    # Mock POSIX environment and stat mode with group-readable bit (0o644)
    with patch("os.name", "posix"):
        mock_stat = type("MockStat", (), {"st_mode": 0o100644})()
        with patch.object(Path, "stat", return_value=mock_stat):
            with pytest.raises(SecurityError, match="Insecure permissions"):
                check_file_permissions(secret_file)
