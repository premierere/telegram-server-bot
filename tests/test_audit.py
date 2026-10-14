"""Tests for structured JSON Lines audit logging and admin security alerts."""

import json
from pathlib import Path

import pytest

from src.audit import AuditEvent, AuditLogger


@pytest.mark.asyncio
async def test_audit_log_writing_and_no_secrets(tmp_path: Path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit_file_path=log_file, echo_stdout=False)

    secret_cmd = "login with token=123456789:ABCDefGhIJKlmNoPQRsTUVwxyZ123456789"
    event = AuditEvent(
        user_id=1001,
        chat_id=1001,
        message_id=42,
        event_type="command_executed",
        command=secret_cmd,
        decision="allowed",
        reason="ok",
        exit_code=0,
        duration_ms=25.5,
        output_size_bytes=120,
    )

    logger.log(event)
    assert log_file.is_file()

    content = log_file.read_text(encoding="utf-8").strip()
    data = json.loads(content)

    assert data["user_id"] == 1001
    assert data["decision"] == "allowed"
    assert data["event_type"] == "command_executed"

    # Strictly assert that the raw token does NOT appear in the audit log
    assert "123456789:ABCDefGhIJKlmNoPQRsTUVwxyZ123456789" not in content
    assert "[REDACTED]" in data["command"]


@pytest.mark.asyncio
async def test_admin_alerts_dispatch():
    received_alerts = []

    async def mock_admin_notifier(admin_id: int, message: str):
        received_alerts.append((admin_id, message))

    logger = AuditLogger(
        admin_user_ids=[1001, 1002],
        admin_notifier=mock_admin_notifier,
        echo_stdout=False,
    )

    event = AuditEvent(
        user_id=9999,
        event_type="lockout",
        decision="denied",
        reason="too_many_failures",
    )

    alert_msg = "🚨 CẢNH BÁO: Tài khoản 9999 đã bị khóa do nhập sai mã TOTP 5 lần!"
    await logger.log_and_alert(event, alert_message=alert_msg)

    # Both admin 1001 and 1002 should receive the alert
    assert len(received_alerts) == 2
    assert received_alerts[0] == (1001, alert_msg)
    assert received_alerts[1] == (1002, alert_msg)
