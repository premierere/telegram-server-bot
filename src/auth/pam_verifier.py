"""Zero-storage Linux PAM / system credential verifier.

Verifies Linux username and password by invoking system authentication (su/PAM)
via standard input or pipe without ever persisting the password to disk or state.
Provides a mock backend for offline unit testing.
"""

from __future__ import annotations

import asyncio
import os
import re

USERNAME_REGEX = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class LinuxPAMVerifier:
    """Verifies Linux system credentials with zero persistent storage."""

    def __init__(self, mock_backend: bool = False) -> None:
        self.mock_backend = mock_backend
        self._mock_accounts: dict[str, str] = {}

    def set_mock_account(self, username: str, password: str) -> None:
        """Set an in-memory mock account for testing purposes."""
        self._mock_accounts[username] = password

    async def verify_credentials(self, username: str, password: str) -> tuple[bool, str]:
        """Verify username and password against system PAM or mock backend.

        Returns:
            (True, "") if authentication succeeds.
            (False, error_reason) if authentication fails.
        """
        # 1. Strict username validation to prevent injection into su/PAM commands
        clean_user = username.strip()
        if not USERNAME_REGEX.match(clean_user):
            return False, "invalid_username"

        # 2. Mock mode for unit tests and non-Linux development hosts
        if self.mock_backend or os.name == "nt":
            if clean_user not in self._mock_accounts:
                return False, "user_not_found"
            if self._mock_accounts[clean_user] == password:
                return True, ""
            return False, "authentication_failed"

        # 3. Linux POSIX PAM Verification via su -c true
        # Invokes su <username> -c true, passing password via stdin
        try:
            process = await asyncio.create_subprocess_exec(
                "su",
                clean_user,
                "-c",
                "true",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Write password to stdin and close
            input_bytes = (password + "\n").encode("utf-8")
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=input_bytes),
                timeout=5.0,
            )

            if process.returncode == 0:
                return True, ""

            err_msg = stderr.decode(errors="replace")
            if "unknown user" in err_msg.lower() or "user not found" in err_msg.lower():
                return False, "user_not_found"
            return False, "authentication_failed"

        except asyncio.TimeoutError:
            try:
                process.kill()
            except Exception:
                pass
            return False, "authentication_timeout"
        except Exception as exc:
            return False, f"system_error: {exc}"
