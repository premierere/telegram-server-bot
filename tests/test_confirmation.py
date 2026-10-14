"""Tests for dangerous command confirmation, nonce binding, and tamper resistance."""


from src.auth.confirmation import ConfirmationManager, compute_command_hash


def test_confirmation_lifecycle():
    mgr = ConfirmationManager(default_expiry_seconds=30.0)
    cmd = "rm -rf /srv/app/old_releases"

    # 1. Create confirmation
    pending = mgr.create_confirmation(
        user_id=1001,
        chat_id=1001,
        command_text=cmd,
        current_time=1000.0,
    )
    assert pending.user_id == 1001
    assert pending.command_hash == compute_command_hash(cmd)
    mgr.set_message_id(pending.nonce, 42)

    # 2. Verify successfully within 30s
    success, reason, verified = mgr.verify_and_consume(
        nonce=pending.nonce,
        user_id=1001,
        chat_id=1001,
        message_id=42,
        command_text=cmd,
        current_time=1015.0,
    )
    assert success is True
    assert reason is None
    assert verified.command_text == cmd

    # 3. Replay attempt: nonce is already consumed
    replay_success, replay_reason, _ = mgr.verify_and_consume(
        nonce=pending.nonce,
        user_id=1001,
        chat_id=1001,
        message_id=42,
        command_text=cmd,
        current_time=1016.0,
    )
    assert replay_success is False
    assert replay_reason == "invalid_or_expired_nonce"


def test_expired_confirmation():
    mgr = ConfirmationManager(default_expiry_seconds=30.0)
    pending = mgr.create_confirmation(
        user_id=1001,
        chat_id=1001,
        command_text="reboot",
        current_time=1000.0,
    )

    # Attempt after 31s
    success, reason, _ = mgr.verify_and_consume(
        nonce=pending.nonce,
        user_id=1001,
        chat_id=1001,
        current_time=1031.0,
    )
    assert success is False
    assert reason == "confirmation_expired"


def test_user_mismatch_rejected():
    mgr = ConfirmationManager()
    pending = mgr.create_confirmation(
        user_id=1001,
        chat_id=1001,
        command_text="shutdown -h now",
    )

    # Different user attempts to confirm
    success, reason, _ = mgr.verify_and_consume(
        nonce=pending.nonce,
        user_id=9999,
        chat_id=1001,
    )
    assert success is False
    assert reason == "user_id_mismatch"


def test_message_id_mismatch_rejected():
    mgr = ConfirmationManager()
    pending = mgr.create_confirmation(
        user_id=1001,
        chat_id=1001,
        command_text="iptables -F",
        message_id=100,
    )

    # Button from different message pressed
    success, reason, _ = mgr.verify_and_consume(
        nonce=pending.nonce,
        user_id=1001,
        chat_id=1001,
        message_id=101,
    )
    assert success is False
    assert reason == "message_id_mismatch"


def test_command_swap_tamper_rejected():
    mgr = ConfirmationManager()
    pending = mgr.create_confirmation(
        user_id=1001,
        chat_id=1001,
        command_text="systemctl restart nginx",
    )

    # Attacker tries to confirm a different command using the same nonce
    success, reason, _ = mgr.verify_and_consume(
        nonce=pending.nonce,
        user_id=1001,
        chat_id=1001,
        command_text="rm -rf /",
    )
    assert success is False
    assert reason == "command_hash_mismatch"


def test_cancellation():
    mgr = ConfirmationManager()
    pending = mgr.create_confirmation(user_id=1001, chat_id=1001, command_text="reboot")
    assert mgr.cancel(pending.nonce) is True
    # Once cancelled, cannot be verified
    success, reason, _ = mgr.verify_and_consume(nonce=pending.nonce, user_id=1001, chat_id=1001)
    assert success is False
