"""Tests for JobManager: concurrency caps, rate limiting, and job termination."""

from unittest.mock import MagicMock

import pytest

from src.executor.jobs import JobManager


def test_concurrency_cap():
    mgr = JobManager(max_concurrent_jobs=2)

    assert mgr.can_acquire_slot() is True

    # Register 1st job
    job1 = mgr.register_job(user_id=1001, command_display="uptime")
    assert mgr.can_acquire_slot() is True

    # Register 2nd job
    job2 = mgr.register_job(user_id=1001, command_display="free -m")
    assert job2.job_id is not None
    # Slot cap reached
    assert mgr.can_acquire_slot() is False

    # Complete 1st job
    mgr.unregister_job(job1.job_id)
    assert mgr.can_acquire_slot() is True


def test_rate_limiter_sliding_window():
    mgr = JobManager(rate_limit_commands_per_minute=3)
    user_id = 1001

    # 3 commands within window: allowed
    mgr.record_command_attempt(user_id, current_time=1000.0)
    mgr.record_command_attempt(user_id, current_time=1010.0)
    mgr.record_command_attempt(user_id, current_time=1020.0)

    # 4th command at 1030s: rate limited!
    is_allowed, wait_seconds = mgr.check_rate_limit(user_id, current_time=1030.0)
    assert is_allowed is False
    assert wait_seconds > 0

    # At 1061s (first command expired > 60s ago): allowed again!
    is_allowed, wait_seconds = mgr.check_rate_limit(user_id, current_time=1061.0)
    assert is_allowed is True
    assert wait_seconds == 0


@pytest.mark.asyncio
async def test_kill_job():
    mgr = JobManager()
    mock_process = MagicMock()
    mock_process.returncode = None
    mock_process.pid = 12345

    mock_task = MagicMock()
    mock_task.done.return_value = False

    job = mgr.register_job(
        user_id=1001,
        command_display="long_job",
        process=mock_process,
        task=mock_task,
    )

    success, msg = await mgr.kill_job(job.job_id)
    assert success is True
    assert msg == "killed"
    assert mgr.get_job(job.job_id) is None
    assert mock_task.cancel.called
