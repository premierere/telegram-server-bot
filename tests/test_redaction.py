"""Tests for output sanitization, secret redaction, and ANSI stripping."""

import pytest

from src.redaction import (
    format_html_pre,
    redact_secrets,
    sanitize_output,
    strip_ansi,
)


def test_strip_ansi_escapes():
    colored_text = "\x1B[31mError:\x1B[0m \x1B[1mFile not found\x1B[0m\x1B[2K\r"
    cleaned = strip_ansi(colored_text)
    assert cleaned == "Error: File not found\r"
    assert "\x1B" not in cleaned


def test_redact_telegram_token():
    text = "Connecting with token 123456789:ABCDefGhIJKlmNoPQRsTUVwxyZ123456789 to API"
    redacted = redact_secrets(text)
    assert "123456789:ABCDefGhIJKlmNoPQRsTUVwxyZ123456789" not in redacted
    assert "[REDACTED_TELEGRAM_TOKEN]" in redacted


def test_redact_private_key():
    rsa_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y123456789abcdefghijklmnopqrstuvwxyz\n"
        "-----END RSA PRIVATE KEY-----"
    )
    text = f"Certificate loaded:\n{rsa_key}\nServer started"
    redacted = redact_secrets(text)
    assert "MIIEowIBAAKCAQEA" not in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted


def test_redact_key_value_passwords():
    text = (
        "db_config: password=super_secret_db_pass; host=localhost\n"
        "api_key: sk_live_999988887777\n"
        "access_key = secret_token_value\n"
    )
    redacted = redact_secrets(text)
    assert "super_secret_db_pass" not in redacted
    assert "sk_live_999988887777" not in redacted
    assert "secret_token_value" not in redacted
    assert "password=[REDACTED]" in redacted
    assert "api_key:[REDACTED]" in redacted


def test_redact_aws_access_key():
    text = "Exported AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE into environment"
    redacted = redact_secrets(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED_AWS_KEY]" in redacted


def test_format_html_pre():
    raw = "<div>Hello & welcome! 'quotes' and \"double\"</div>"
    formatted = format_html_pre(raw)
    assert "<div>" not in formatted
    assert "&lt;div&gt;" in formatted
    assert "&amp;" in formatted
    assert formatted.startswith("<pre><code class='language-text'>")
    assert formatted.endswith("</code></pre>")


def test_sanitize_output_combines_ansi_and_redaction():
    raw_bytes = b"\x1b[32mSUCCESS:\x1b[0m token=123456789:ABCDefGhIJKlmNoPQRsTUVwxyZ123456789"
    sanitized = sanitize_output(raw_bytes)
    assert "\x1b" not in sanitized
    assert "123456789:ABCDefGhIJKlmNoPQRsTUVwxyZ123456789" not in sanitized
    assert "[REDACTED]" in sanitized
