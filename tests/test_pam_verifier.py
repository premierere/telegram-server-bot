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
