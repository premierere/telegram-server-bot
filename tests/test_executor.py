"""Tests for ProcessExecutor: process groups, streaming cap, timeouts, and env allowlisting."""

import os
import sys
from pathlib import Path

import pytest

from src.executor.process import ProcessExecutor, build_sanitized_env


@pytest.mark.asyncio
async def test_successful_argv_execution():
    executor = ProcessExecutor()
    result = await executor.execute(argv=[sys.executable, "-c", "print('hello from subprocess')"])
    assert result.exit_code == 0
    assert b"hello from subprocess" in result.stdout
    assert not result.is_timeout
    assert not result.is_truncated


@pytest.mark.asyncio
async def test_environment_sanitization():
    # Set sensitive tokens in parent environment
    os.environ["TELEGRAM_BOT_TOKEN"] = "leaked_token_12345"
    os.environ["TOTP_SECRET"] = "JBSWY3DPEHPK3PXP"

    executor = ProcessExecutor()
    # Script dumps all environment variable names
    script = (
        "import os\n"
        "keys = set(os.environ.keys())\n"
        "assert 'TELEGRAM_BOT_TOKEN' not in keys\n"
        "assert 'TOTP_SECRET' not in keys\n"
        "print('ENV_CLEAN')\n"
    )
    result = await executor.execute(argv=[sys.executable, "-c", script])
    assert result.exit_code == 0
    assert b"ENV_CLEAN" in result.stdout

    # Clean up test env
    os.environ.pop("TELEGRAM_BOT_TOKEN", None)
    os.environ.pop("TOTP_SECRET", None)


@pytest.mark.asyncio
async def test_process_timeout_kills_process():
    executor = ProcessExecutor(grace_period_seconds=0.5)
    # Long sleeping subprocess
    script = "import time; time.sleep(10)"
    result = await executor.execute(
        argv=[sys.executable, "-c", script],
        timeout_seconds=0.5,
    )
    assert result.is_timeout is True
    assert result.is_killed is True


@pytest.mark.asyncio
async def test_streaming_output_cap_truncates_and_kills():
    # Max output set to 5000 bytes
    executor = ProcessExecutor(max_output_bytes=5000, grace_period_seconds=0.5)
    # Script generates infinite output
    script = "import sys\nwhile True:\n    sys.stdout.write('A' * 1000)\n    sys.stdout.flush()\n"
    result = await executor.execute(
        argv=[sys.executable, "-c", script],
        timeout_seconds=5.0,
    )
    assert result.is_truncated is True
    assert result.is_killed is True
    assert len(result.stdout) <= 6000  # 5000 + truncation warning message
    assert b"OUTPUT TRUNCATED" in result.stdout


@pytest.mark.asyncio
async def test_stdin_is_devnull():
    executor = ProcessExecutor()
    # Trying to read from stdin returns EOF immediately
    script = "import sys; data = sys.stdin.read(); print(f'READ:{len(data)}')"
    result = await executor.execute(argv=[sys.executable, "-c", script])
    assert result.exit_code == 0
    assert b"READ:0" in result.stdout
