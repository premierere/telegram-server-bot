"""Configuration loading and strict fail-closed validation.

Handles file permissions checking, systemd credentials loading, and ensures
that only authorized numeric user IDs and strictly typed configurations are accepted.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigurationError(Exception):
    """Raised when configuration syntax, types, or constraints are invalid."""


class SecurityError(Exception):
    """Raised when security boundaries (permissions, root user, etc.) are violated."""


ALLOWED_ROOT_KEYS = {
    "allowed_user_ids",
    "admin_user_ids",
    "users",
    "bot_token_file",
    "totp_dir",
    "policy_file",
    "audit_file",
    "work_dir",
    "limits",
}

ALLOWED_LIMIT_KEYS = {
    "session_idle_timeout_seconds",
    "session_absolute_timeout_seconds",
    "command_default_timeout_seconds",
    "command_max_timeout_seconds",
    "max_concurrent_jobs",
    "rate_limit_commands_per_minute",
    "message_max_age_seconds",
    "totp_max_clock_drift_steps",
    "totp_lockout_threshold",
    "confirmation_timeout_seconds",
    "max_inline_output_chars",
    "max_document_output_bytes",
}

ALLOWED_USER_KEYS = {"mode"}
ALLOWED_MODES = {"restricted", "shell"}


@dataclass(frozen=True)
class LimitsConfig:
    """Security limits and timeouts."""

    session_idle_timeout_seconds: int = 600
    session_absolute_timeout_seconds: int = 3600
    command_default_timeout_seconds: int = 30
    command_max_timeout_seconds: int = 300
    max_concurrent_jobs: int = 2
    rate_limit_commands_per_minute: int = 10
    message_max_age_seconds: int = 60
    totp_max_clock_drift_steps: int = 1
    totp_lockout_threshold: int = 5
    confirmation_timeout_seconds: int = 30
    max_inline_output_chars: int = 3500
    max_document_output_bytes: int = 1048576  # 1 MB


@dataclass(frozen=True)
class UserConfig:
    """Per-user configuration settings."""

    mode: str = "restricted"


@dataclass(frozen=True)
class Config:
    """Validated top-level application configuration."""

    allowed_user_ids: list[int]
    admin_user_ids: list[int]
    users: dict[int, UserConfig]
    bot_token: str
    bot_token_file: str | None
    totp_dir: str
    policy_file: str
    audit_file: str
    work_dir: str
    limits: LimitsConfig = field(default_factory=LimitsConfig)


def check_root_user() -> None:
    """Refuse to run if current process has root privileges."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SecurityError(
            "Running as root is strictly forbidden. Use a dedicated unprivileged user."
        )


def check_file_permissions(path: str | Path, allow_non_existent: bool = False) -> None:
    """Verify that sensitive files are not readable or writable by group or others (0600/0400)."""
    p = Path(path)
    if not p.exists():
        if allow_non_existent:
            return
        raise ConfigurationError(f"Required file does not exist: {p}")

    # Check POSIX permissions if on POSIX platform
    if hasattr(os, "stat") and os.name == "posix":
        mode = p.stat().st_mode
        if mode & 0o077 != 0:
            raise SecurityError(
                f"Insecure permissions on {p} (mode {oct(mode)}): "
                "must not be readable or writable by group or others (e.g. chmod 600 or 400)."
            )


def resolve_bot_token(
    bot_token_file: str | None = None,
    enforce_file_perms: bool = True,
) -> str:
    """Resolve the Telegram bot token following strict precedence.

    Order of resolution:
    1. Systemd Credential: $CREDENTIALS_DIRECTORY/bot_token
    2. File configured via bot_token_file (with 0600/0400 permission check)
    3. Environment variable TELEGRAM_BOT_TOKEN
    """
    # 1. Systemd Credential
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if creds_dir:
        token_cred_path = Path(creds_dir) / "bot_token"
        if token_cred_path.is_file():
            token = token_cred_path.read_text(encoding="utf-8").strip()
            if token:
                return token

    # 2. Configured file path
    if bot_token_file:
        token_path = Path(bot_token_file)
        if token_path.is_file():
            if enforce_file_perms:
                check_file_permissions(token_path)
            token = token_path.read_text(encoding="utf-8").strip()
            if token:
                return token

    # 3. Environment variable
    env_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if env_token:
        return env_token

    raise ConfigurationError(
        "No Telegram bot token found. Provide systemd credential "
        "($CREDENTIALS_DIRECTORY/bot_token), bot_token_file, or TELEGRAM_BOT_TOKEN."
    )


def load_config(
    config_path: str | Path,
    enforce_file_perms: bool = True,
    override_token: str | None = None,
) -> Config:
    """Load, validate, and return the application configuration.

    Fails closed immediately on:
    - Root execution
    - Insecure file permissions
    - Unknown configuration keys
    - Invalid data types or values
    - Empty or missing allowlist
    - Missing bot token
    """
    check_root_user()

    p = Path(config_path)
    if not p.is_file():
        raise ConfigurationError(f"Configuration file not found: {p}")

    if enforce_file_perms:
        check_file_permissions(p)

    try:
        content = p.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
    except Exception as exc:
        raise ConfigurationError(f"Failed to parse YAML configuration: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigurationError("Configuration root must be a YAML mapping.")

    # Check for unknown root keys
    unknown_root_keys = set(data.keys()) - ALLOWED_ROOT_KEYS
    if unknown_root_keys:
        raise ConfigurationError(
            f"Unknown configuration key(s) detected: {sorted(unknown_root_keys)}"
        )

    # Validate allowed_user_ids
    raw_allowed = data.get("allowed_user_ids")
    if not raw_allowed or not isinstance(raw_allowed, list):
        raise ConfigurationError("allowed_user_ids must be a non-empty list of numeric user IDs.")

    allowed_user_ids: list[int] = []
    for uid in raw_allowed:
        if not isinstance(uid, int) or isinstance(uid, bool):
            raise ConfigurationError(
                f"Invalid user ID '{uid}' in allowed_user_ids: must be an integer."
            )
        allowed_user_ids.append(uid)

    # Validate admin_user_ids
    raw_admins = data.get("admin_user_ids", [])
    if not isinstance(raw_admins, list):
        raise ConfigurationError("admin_user_ids must be a list of numeric user IDs.")

    admin_user_ids: list[int] = []
    for uid in raw_admins:
        if not isinstance(uid, int) or isinstance(uid, bool):
            raise ConfigurationError(
                f"Invalid user ID '{uid}' in admin_user_ids: must be an integer."
            )
        admin_user_ids.append(uid)

    # Validate users map
    raw_users = data.get("users", {})
    if not isinstance(raw_users, dict):
        raise ConfigurationError("users must be a mapping of user_id to user settings.")

    users: dict[int, UserConfig] = {}
    for uid_key, user_settings in raw_users.items():
        if not isinstance(uid_key, int) or isinstance(uid_key, bool):
            raise ConfigurationError(f"User ID key '{uid_key}' in users mapping must be an integer.")
        if not isinstance(user_settings, dict):
            raise ConfigurationError(f"Settings for user {uid_key} must be a mapping.")

        unknown_u_keys = set(user_settings.keys()) - ALLOWED_USER_KEYS
        if unknown_u_keys:
            raise ConfigurationError(
                f"Unknown user setting(s) for user {uid_key}: {sorted(unknown_u_keys)}"
            )

        mode = user_settings.get("mode", "restricted")
        if mode not in ALLOWED_MODES:
            raise ConfigurationError(
                f"Invalid mode '{mode}' for user {uid_key}. Must be one of {sorted(ALLOWED_MODES)}."
            )
        users[uid_key] = UserConfig(mode=mode)

    # Ensure all allowed users have a UserConfig entry (defaulting to restricted)
    for uid in allowed_user_ids:
        if uid not in users:
            users[uid] = UserConfig(mode="restricted")

    # Validate limits
    raw_limits = data.get("limits", {})
    if not isinstance(raw_limits, dict):
        raise ConfigurationError("limits must be a mapping of limit settings.")

    unknown_limit_keys = set(raw_limits.keys()) - ALLOWED_LIMIT_KEYS
    if unknown_limit_keys:
        raise ConfigurationError(
            f"Unknown limit setting(s) detected: {sorted(unknown_limit_keys)}"
        )

    for k, v in raw_limits.items():
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            raise ConfigurationError(f"Limit '{k}' must be a positive integer, got: {v}")

    limits = LimitsConfig(**raw_limits)
    if limits.command_default_timeout_seconds > limits.command_max_timeout_seconds:
        raise ConfigurationError(
            f"command_default_timeout_seconds ({limits.command_default_timeout_seconds}) "
            f"cannot exceed command_max_timeout_seconds ({limits.command_max_timeout_seconds})."
        )

    # Validate paths
    bot_token_file = data.get("bot_token_file")
    if bot_token_file is not None and not isinstance(bot_token_file, str):
        raise ConfigurationError("bot_token_file must be a string path or null.")

    totp_dir = data.get("totp_dir", "/var/lib/telegram-server-bot/totp")
    if not isinstance(totp_dir, str):
        raise ConfigurationError("totp_dir must be a string path.")

    policy_file = data.get("policy_file", "policy.yaml")
    if not isinstance(policy_file, str):
        raise ConfigurationError("policy_file must be a string path.")

    audit_file = data.get("audit_file", "/var/log/telegram-server-bot/audit.jsonl")
    if not isinstance(audit_file, str):
        raise ConfigurationError("audit_file must be a string path.")

    work_dir = data.get("work_dir", "/var/lib/telegram-server-bot/sandbox")
    if not isinstance(work_dir, str):
        raise ConfigurationError("work_dir must be a string path.")

    # Resolve token
    if override_token:
        bot_token = override_token
    else:
        bot_token = resolve_bot_token(
            bot_token_file=bot_token_file,
            enforce_file_perms=enforce_file_perms,
        )

    return Config(
        allowed_user_ids=allowed_user_ids,
        admin_user_ids=admin_user_ids,
        users=users,
        bot_token=bot_token,
        bot_token_file=bot_token_file,
        totp_dir=totp_dir,
        policy_file=policy_file,
        audit_file=audit_file,
        work_dir=work_dir,
        limits=limits,
    )
