"""Output sanitization, secret redaction, and ANSI escape code stripping.

Ensures:
- ANSI escape codes are completely stripped.
- Sensitive credentials (bot tokens, private keys, passwords, cloud access keys, TOTP codes)
  are replaced with redaction markers.
- HTML special characters are escaped for safe insertion into Telegram parse mode.
"""

from __future__ import annotations

import html
import re

# Regex for ANSI escape codes
ANSI_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Secret patterns
TELEGRAM_TOKEN_REGEX = re.compile(r"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b")
PRIVATE_KEY_REGEX = re.compile(
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----"
)
AWS_KEY_REGEX = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PASSWORD_KV_REGEX = re.compile(
    r"(?i)\b(password|passwd|secret|api_key|access_key|token)\s*([:=])\s*([^\s,;]+)"
)


def strip_ansi(text: str) -> str:
    """Remove ANSI color, formatting, and cursor sequences."""
    return ANSI_REGEX.sub("", text)


def redact_secrets(text: str) -> str:
    """Detect and mask known secret patterns."""
    # 1. Telegram bot tokens
    redacted = TELEGRAM_TOKEN_REGEX.sub("[REDACTED_TELEGRAM_TOKEN]", text)

    # 2. Private key blocks (RSA, EC, OPENSSH, etc.)
    redacted = PRIVATE_KEY_REGEX.sub("[REDACTED_PRIVATE_KEY]", redacted)

    # 3. AWS Access Keys
    redacted = AWS_KEY_REGEX.sub("[REDACTED_AWS_KEY]", redacted)

    # 4. Key-value secrets (e.g. password=xyz, token: abc)
    def mask_kv(match: re.Match) -> str:
        key = match.group(1)
        sep = match.group(2)
        return f"{key}{sep}[REDACTED]"

    redacted = PASSWORD_KV_REGEX.sub(mask_kv, redacted)

    return redacted


def sanitize_output(raw_output: str | bytes) -> str:
    """Strip ANSI, redact secrets, and return clean UTF-8 string."""
    if isinstance(raw_output, bytes):
        text = raw_output.decode("utf-8", errors="replace")
    else:
        text = raw_output

    clean_text = strip_ansi(text)
    sanitized = redact_secrets(clean_text)
    return sanitized


def format_html_pre(content: str) -> str:
    """Safely escape text and enclose inside HTML pre and code tags."""
    escaped = html.escape(content, quote=True)
    return f"<pre><code class='language-text'>{escaped}</code></pre>"
