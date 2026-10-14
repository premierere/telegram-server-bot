"""Zero-storage Linux PAM / system credential verifier.

Verifies Linux username and password by invoking system authentication (su/PAM)
via standard input or pipe without ever persisting the password to disk or state.
Provides a mock backend for offline unit testing.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil

USERNAME_REGEX = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$")


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
        # 1. Strict username validation to prevent injection
        clean_user = username.strip()
        if not USERNAME_REGEX.match(clean_user):
            return False, "invalid_username"

        # 2. Mock mode for unit tests and non-Linux development hosts
        if self.mock_backend or os.name == "nt":
            # Support case-insensitive fallback in mock mode (e.g. mobile auto-capitalization)
            lookup_user = clean_user
            if lookup_user not in self._mock_accounts and lookup_user.lower() in self._mock_accounts:
                lookup_user = lookup_user.lower()

            if lookup_user not in self._mock_accounts:
                return False, "user_not_found"
            if self._mock_accounts[lookup_user] == password:
                return True, ""
            return False, "authentication_failed"

        # 3. Linux POSIX verification
        # First verify account existence via pwd module (with lowercase fallback)
        actual_user = clean_user
        try:
            import pwd

            try:
                pw_record = pwd.getpwnam(clean_user)
                actual_user = pw_record.pw_name
            except KeyError:
                try:
                    pw_record = pwd.getpwnam(clean_user.lower())
                    actual_user = pw_record.pw_name
                except KeyError:
                    return False, "user_not_found"
        except ImportError:
            pass

        # Execute PTY-based su verification in background thread to avoid blocking event loop
        return await asyncio.to_thread(self._verify_via_su_pty, actual_user, password)

    def _verify_via_su_pty(self, username: str, password: str, timeout: float = 6.0) -> tuple[bool, str]:
        """Verify password by running su inside a real pseudo-terminal (PTY).

        Standard su reads passwords from /dev/tty via libc getpass(), not stdin pipe.
        Running su inside an allocated PTY pair provides a real TTY slave so getpass()
        reads the provided password correctly without hanging or requiring stdin pipe.
        """
        import pty
        import select
        import subprocess
        import time

        su_binary = shutil.which("su") or "/bin/su"
        if not os.path.exists(su_binary):
            return False, "su_not_installed"

        try:
            master_fd, slave_fd = pty.openpty()
        except Exception as exc:
            return False, f"system_error: pty_open_failed ({exc})"

        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
        }

        try:
            proc = subprocess.Popen(
                [su_binary, username, "-c", "true"],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                env=env,
            )
        except Exception as exc:
            os.close(master_fd)
            os.close(slave_fd)
            return False, f"system_error: su_exec_failed ({exc})"

        # Close slave_fd in parent so EOF is detectable
        os.close(slave_fd)

        start_time = time.monotonic()
        password_sent = False
        output_chunks: list[bytes] = []

        try:
            while time.monotonic() - start_time < timeout:
                if proc.poll() is not None:
                    break

                r, _, _ = select.select([master_fd], [], [], 0.05)
                if r:
                    try:
                        data = os.read(master_fd, 1024)
                    except OSError:
                        # Slave closed on child exit
                        break

                    if not data:
                        break
                    output_chunks.append(data)

                    # Prompt arrived; send password followed by newline
                    if not password_sent:
                        try:
                            os.write(master_fd, (password + "\n").encode("utf-8"))
                            password_sent = True
                        except OSError:
                            break

                elif not password_sent and (time.monotonic() - start_time >= 0.15):
                    # In case prompt was unbuffered, send password after 150ms
                    try:
                        os.write(master_fd, (password + "\n").encode("utf-8"))
                        password_sent = True
                    except OSError:
                        break

            # Wait for child process to terminate
            rem_timeout = max(0.5, timeout - (time.monotonic() - start_time))
            try:
                return_code = proc.wait(timeout=rem_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                return False, "authentication_timeout"

            if return_code == 0:
                return True, ""

            combined = b"".join(output_chunks).decode("utf-8", errors="replace").lower()
            if "does not exist" in combined or "unknown user" in combined or "not found" in combined:
                return False, "user_not_found"

            return False, "authentication_failed"

        finally:
            try:
                os.close(master_fd)
            except OSError:
                pass
            if proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass
