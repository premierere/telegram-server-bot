"""Tests for LinuxPAMVerifier zero-storage credential check."""

import pytest

from src.auth.pam_verifier import LinuxPAMVerifier


@pytest.mark.asyncio
async def test_pam_verifier_mock_mode():
    verifier = LinuxPAMVerifier(mock_backend=True)
    verifier.set_mock_account("guest", "ValidPass123!")

    # 1. Correct credentials
    success, err = await verifier.verify_credentials("guest", "ValidPass123!")
    assert success is True
    assert err == ""

    # 2. Incorrect password
    success, err = await verifier.verify_credentials("guest", "WrongPassword")
    assert success is False
    assert "authentication_failed" in err.lower()

    # 3. Non-existent account
    success, err = await verifier.verify_credentials("nonexistent_user", "AnyPass")
    assert success is False
    assert "user_not_found" in err.lower()


@pytest.mark.asyncio
async def test_username_validation():
    verifier = LinuxPAMVerifier(mock_backend=True)
    # Reject shell injection characters in username
    success, err = await verifier.verify_credentials("root; rm -rf /", "pass")
    assert success is False
    assert "invalid_username" in err.lower()

    success, err = await verifier.verify_credentials("-bad_start", "pass")
    assert success is False
    assert "invalid_username" in err.lower()


@pytest.mark.asyncio
async def test_case_insensitive_username_fallback():
    verifier = LinuxPAMVerifier(mock_backend=True)
    verifier.set_mock_account("ubuntu", "UbuntuPass123!")

    # Mobile auto-capitalized "Ubuntu" should match "ubuntu"
    success, err = await verifier.verify_credentials("Ubuntu", "UbuntuPass123!")
    assert success is True
    assert err == ""

    # Wrong password with capitalized username should still report authentication_failed
    success, err = await verifier.verify_credentials("Ubuntu", "WrongPass")
    assert success is False
    assert err == "authentication_failed"


def test_su_pty_execution_success(monkeypatch):
    """Simulate PTY openpty execution on POSIX systems."""
    import sys
    from unittest.mock import MagicMock

    # Mock pty, os.read, os.write, select, subprocess
    fake_proc = MagicMock()
    fake_proc.poll.side_effect = [None, 0, 0, 0, 0]
    fake_proc.wait.return_value = 0

    monkeypatch.setattr("shutil.which", lambda cmd: "/bin/su")
    monkeypatch.setattr("os.path.exists", lambda path: True)

    import subprocess

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: fake_proc)

    # Mock pty module if on Windows
    fake_pty = MagicMock()
    fake_pty.openpty.return_value = (10, 11)
    monkeypatch.setitem(sys.modules, "pty", fake_pty)

    monkeypatch.setattr("os.close", lambda fd: None)
    monkeypatch.setattr("os.read", lambda fd, n: b"Password: ")
    monkeypatch.setattr("os.write", lambda fd, data: len(data))

    import select

    monkeypatch.setattr(select, "select", lambda r, w, x, t: ([10], [], []))

    verifier = LinuxPAMVerifier(mock_backend=False)
    success = verifier._verify_via_su_pty("ubuntu", "SecretPass123")
    assert success is True


def test_pty_fork_execution_simulation(monkeypatch):
    """Simulate pty.fork parent execution with successful exit code."""
    import sys
    from unittest.mock import MagicMock

    monkeypatch.setattr("shutil.which", lambda cmd: "/bin/su")
    monkeypatch.setattr("os.path.exists", lambda path: True)

    # Mock pty.fork
    fake_pty = MagicMock()
    fake_pty.fork.return_value = (12345, 99)
    monkeypatch.setitem(sys.modules, "pty", fake_pty)

    # Mock os functions
    monkeypatch.setattr("os.close", lambda fd: None)
    monkeypatch.setattr("os.waitpid", lambda pid, flags: (12345, 0))
    monkeypatch.setattr("os.waitstatus_to_exitcode", lambda status: 0)

    import select

    monkeypatch.setattr(select, "select", lambda r, w, x, t: ([], [], []))

    verifier = LinuxPAMVerifier(mock_backend=False)
    success = verifier._verify_via_pty_fork("ubuntu", "SecretPass123")
    assert success is True
