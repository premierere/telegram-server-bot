"""Job management, concurrency cap, and rate limiting.

Enforces:
- Global concurrency limit (default 2 active jobs).
- Per-user rate limiting (default 10 commands per minute).
- Job registration, status inspection (/jobs), and process cancellation (/kill).
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass
from typing import Any

from src.executor.process import kill_process_tree


@dataclass
class Job:
    """Represents an ongoing asynchronous command job."""

    job_id: str
    user_id: int
    command_display: str
    start_time: float
    process: asyncio.subprocess.Process | None = None
    task: asyncio.Task | None = None

    @property
    def elapsed_seconds(self) -> float:
        """Seconds since job was started."""
        return time.monotonic() - self.start_time

    @property
    def pid(self) -> int | None:
        """Process PID if available."""
        return self.process.pid if self.process else None


class JobManager:
    """Tracks active jobs, enforces global concurrency caps, and manages per-user rate limits."""

    def __init__(
        self,
        max_concurrent_jobs: int = 2,
        rate_limit_commands_per_minute: int = 10,
    ) -> None:
        self.max_concurrent_jobs = max_concurrent_jobs
        self.rate_limit_commands_per_minute = rate_limit_commands_per_minute

        self._active_jobs: dict[str, Job] = {}
        # user_id -> list of monotonic timestamps of recent command attempts
        self._user_command_history: dict[int, list[float]] = {}
        self._lock = asyncio.Lock()

    def check_rate_limit(self, user_id: int, current_time: float | None = None) -> tuple[bool, int]:
        """Check if user has exceeded their rate limit.

        Returns:
            (is_allowed, wait_seconds)
        """
        now = time.monotonic() if current_time is None else current_time
        history = self._user_command_history.get(user_id, [])

        # Prune timestamps older than 60 seconds
        cutoff = now - 60.0
        valid_history = [t for t in history if t > cutoff]
        self._user_command_history[user_id] = valid_history

        if len(valid_history) >= self.rate_limit_commands_per_minute:
            # Wait time is based on the oldest timestamp in window
            oldest = valid_history[0]
            wait_seconds = max(1, int(60.0 - (now - oldest)))
            return False, wait_seconds

        return True, 0

    def record_command_attempt(self, user_id: int, current_time: float | None = None) -> None:
        """Record command execution timestamp for user rate-limiting."""
        now = time.monotonic() if current_time is None else current_time
        if user_id not in self._user_command_history:
            self._user_command_history[user_id] = []
        self._user_command_history[user_id].append(now)

    def can_acquire_slot(self) -> bool:
        """Check if a new job can be started without exceeding the concurrency cap."""
        return len(self._active_jobs) < self.max_concurrent_jobs

    def register_job(
        self,
        user_id: int,
        command_display: str,
        process: asyncio.subprocess.Process | None = None,
        task: asyncio.Task | None = None,
    ) -> Job:
        """Register a new active job with a unique job ID."""
        job_id = f"job-{secrets.token_hex(4)}"
        job = Job(
            job_id=job_id,
            user_id=user_id,
            command_display=command_display,
            start_time=time.monotonic(),
            process=process,
            task=task,
        )
        self._active_jobs[job_id] = job
        return job

    def unregister_job(self, job_id: str) -> None:
        """Remove a job when finished."""
        self._active_jobs.pop(job_id, None)

    def list_jobs(self) -> list[Job]:
        """Return list of currently active jobs."""
        return list(self._active_jobs.values())

    def get_job(self, job_id: str) -> Job | None:
        """Get job by ID."""
        return self._active_jobs.get(job_id)

    async def kill_job(self, job_id: str) -> tuple[bool, str]:
        """Cancel and terminate a running job."""
        job = self._active_jobs.get(job_id)
        if not job:
            return False, "job_not_found"

        if job.process and job.process.returncode is None:
            kill_process_tree(job.process.pid)

        if job.task and not job.task.done():
            job.task.cancel()

        self.unregister_job(job_id)
        return True, "killed"
