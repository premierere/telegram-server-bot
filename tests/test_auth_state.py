"""Tests for multi-step authentication state machine and password retry loop."""

from src.auth.state import AuthStage, AuthStateManager


def test_auth_state_initial_state():
    mgr = AuthStateManager()
    user_id = 1001
    assert mgr.get_stage(user_id) == AuthStage.UNAUTHENTICATED
    assert mgr.get_pending_username(user_id) is None


def test_auth_state_totp_to_username_to_password():
    mgr = AuthStateManager()
    user_id = 1001

    # 1. Pass TOTP -> moves to AWAITING_USERNAME
    mgr.set_stage(user_id, AuthStage.AWAITING_USERNAME)
    assert mgr.get_stage(user_id) == AuthStage.AWAITING_USERNAME

    # 2. Enter username -> moves to AWAITING_PASSWORD
    mgr.set_stage(user_id, AuthStage.AWAITING_PASSWORD, pending_username="root")
    assert mgr.get_stage(user_id) == AuthStage.AWAITING_PASSWORD
    assert mgr.get_pending_username(user_id) == "root"


def test_auth_state_password_retry_loop_and_lockout_to_username():
    mgr = AuthStateManager()
    user_id = 1001
    mgr.set_stage(user_id, AuthStage.AWAITING_PASSWORD, pending_username="ubuntu")

    # Failures 1 through 4 remain in AWAITING_PASSWORD
    for attempt in range(1, 5):
        next_stage, attempts = mgr.record_password_failure(user_id)
        assert next_stage == AuthStage.AWAITING_PASSWORD
        assert attempts == attempt
        assert mgr.get_stage(user_id) == AuthStage.AWAITING_PASSWORD

    # 5th failure reverts to AWAITING_USERNAME and resets failure count
    next_stage, attempts = mgr.record_password_failure(user_id)
    assert next_stage == AuthStage.AWAITING_USERNAME
    assert attempts == 5
    assert mgr.get_stage(user_id) == AuthStage.AWAITING_USERNAME
    assert mgr.get_password_failures(user_id) == 0
    assert mgr.get_pending_username(user_id) is None


def test_auth_state_successful_login_and_logout_vs_exit():
    mgr = AuthStateManager()
    user_id = 1001

    # Full login
    mgr.set_stage(user_id, AuthStage.AWAITING_PASSWORD, pending_username="root")
    mgr.complete_authentication(user_id, active_username="root")
    assert mgr.get_stage(user_id) == AuthStage.AUTHENTICATED
    assert mgr.get_active_username(user_id) == "root"

    # /logout: reverts to AWAITING_USERNAME (keeps TOTP valid)
    mgr.logout_to_username(user_id)
    assert mgr.get_stage(user_id) == AuthStage.AWAITING_USERNAME
    assert mgr.get_active_username(user_id) is None

    # /exit: reverts to UNAUTHENTICATED (requires TOTP again)
    mgr.exit_to_unauthenticated(user_id)
    assert mgr.get_stage(user_id) == AuthStage.UNAUTHENTICATED
    assert mgr.get_active_username(user_id) is None
