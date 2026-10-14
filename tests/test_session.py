"""Tests for in-memory session management, idle timeouts, and absolute timeouts."""

import pytest

from src.auth.session import Session, SessionManager


def test_session_lifecycle():
    manager = SessionManager(idle_timeout_seconds=600.0, absolute_timeout_seconds=3600.0)

    # 1. Create session
    session = manager.create_session(user_id=1001, current_time=1000.0)
    assert session.user_id == 1001
    assert session.login_time == 1000.0

    # 2. Retrieve valid session
    retrieved = manager.get_session(user_id=1001, current_time=1200.0)
    assert retrieved is not None
    assert retrieved.user_id == 1001

    # 3. Destroy session (/logout)
    assert manager.destroy_session(1001) is True
    assert manager.get_session(1001) is None


def test_session_idle_timeout():
    manager = SessionManager(idle_timeout_seconds=600.0, absolute_timeout_seconds=3600.0)
    manager.create_session(user_id=1001, current_time=1000.0)

    # Activity at 1500s (500s idle < 600s): valid
    assert manager.touch_session(user_id=1001, current_time=1500.0) is True
    assert manager.get_session(user_id=1001, current_time=1500.0) is not None

    # Inactivity from 1500s to 2150s (650s idle > 600s): expired!
    assert manager.get_session(user_id=1001, current_time=2150.0) is None


def test_session_absolute_timeout():
    manager = SessionManager(idle_timeout_seconds=600.0, absolute_timeout_seconds=3600.0)
    manager.create_session(user_id=1001, current_time=1000.0)

    # Keep touching every 500s up to 4601s (total 3601s > 3600s)
    current = 1000.0
    for _ in range(7):
        current += 500.0
        manager.touch_session(user_id=1001, current_time=current)

    # At 4601s, absolute timeout reached despite being active
    assert manager.get_session(user_id=1001, current_time=4601.0) is None


def test_destroy_all_sessions():
    manager = SessionManager()
    manager.create_session(user_id=1001)
    manager.create_session(user_id=1002)

    manager.destroy_all()
    assert manager.get_session(1001) is None
    assert manager.get_session(1002) is None
