"""Zero-storage Linux PAM / system credential verifier.

Verifies Linux username and password by cascading multiple native authentication mechanisms:
1. Direct /etc/shadow verification via crypt / libcrypt when running as root.
2. Interactive PTY fork via `pty.fork()` with attached controlling terminal for `/bin/su`.
3. PTY openpty fallback with attached session leader for `/bin/su`.
4. In-process PAM C-bindings via ctypes (`libpam.so`) with fallback across services ('common-auth', 'login', 'su').
5. Sudo standard input verification (`sudo -k -S true`) for administrative root elevation on Ubuntu.
6. In-memory mock backend for offline testing on Windows / non-Linux dev hosts.

Passes credentials directly in-memory or through kernel pipes without persisting to disk or state.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil

logger = logging.getLogger(__name__)

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
        """Verify username and password against system PAM, Sudo, or PTY su.

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
            lookup_user = clean_user
            if lookup_user not in self._mock_accounts and lookup_user.lower() in self._mock_accounts:
                lookup_user = lookup_user.lower()

            if lookup_user not in self._mock_accounts:
                return False, "user_not_found"
            clean_pw = password.rstrip("\r\n")
            if self._mock_accounts[lookup_user] in (clean_pw, password.strip()):
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

        # Execute cascading authentication in worker thread to prevent event loop blocking
        return await asyncio.to_thread(self._verify_cascading_posix, actual_user, password)

    def _verify_cascading_posix(self, username: str, password: str) -> tuple[bool, str]:
        """Execute cascading authentication methods on Linux."""
        candidates = [password.rstrip("\r\n")]
        trimmed = password.strip()
        if trimmed and trimmed != candidates[0]:
            candidates.append(trimmed)

        for candidate_pw in candidates:
            # Method 1: Direct /etc/shadow verification (instantaneous if root or shadow readable)
            if self._verify_via_shadow(username, candidate_pw):
                logger.info("Credential verification succeeded via /etc/shadow for user '%s'", username)
                return True, ""

            # Method 2: PTY fork with su (controlling terminal attached, SUID root su handles any account)
            if self._verify_via_pty_fork(username, candidate_pw):
                logger.info("Credential verification succeeded via pty.fork su for user '%s'", username)
                return True, ""

            # Method 3: PTY openpty with su (fallback when fork is constrained)
            if self._verify_via_su_pty(username, candidate_pw):
                logger.info("Credential verification succeeded via openpty su for user '%s'", username)
                return True, ""

            # Method 4: In-process PAM via ctypes (su, login, common-auth)
            for svc in ("su", "login", "common-auth"):
                if self._verify_via_libpam_ctypes(username, candidate_pw, service=svc):
                    logger.info("Credential verification succeeded via libpam (service=%s) for user '%s'", svc, username)
                    return True, ""

            # Method 5: Sudo -S verification (allows root validation with admin user's sudo password on Ubuntu)
            if self._verify_via_sudo(username, candidate_pw):
                logger.info("Credential verification succeeded via sudo -S for user '%s'", username)
                return True, ""

        logger.warning("All credential verification methods failed for user '%s'", username)
        return False, "authentication_failed"

    def _verify_via_shadow(self, username: str, password: str) -> bool:
        """Direct /etc/shadow verification when process has root/shadow permissions."""
        if os.name == "nt":
            return False

        shadow_hash: str | None = None
        try:
            import spwd

            try:
                pw_record = spwd.getspnam(username)
                shadow_hash = pw_record.sp_pwdp
            except KeyError:
                return False
        except Exception:
            pass

        if not shadow_hash:
            try:
                with open("/etc/shadow", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if parts and parts[0] == username:
                            shadow_hash = parts[1]
                            break
            except Exception:
                return False

        if not shadow_hash or shadow_hash in ("*", "!", "x", ""):
            return False

        clean_pw = password.rstrip("\r\n")

        # Verify hash using crypt
        try:
            import crypt

            return crypt.crypt(clean_pw, shadow_hash) == shadow_hash
        except Exception:
            pass

        try:
            import ctypes
            import ctypes.util

            libcrypt_name = ctypes.util.find_library("crypt") or "libcrypt.so.1"
            libcrypt = ctypes.CDLL(libcrypt_name)
            libcrypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            libcrypt.crypt.restype = ctypes.c_char_p
            res = libcrypt.crypt(clean_pw.encode("utf-8"), shadow_hash.encode("utf-8"))
            if res:
                return res.decode("utf-8") == shadow_hash
        except Exception:
            pass

        return False

    def _verify_via_pty_fork(self, username: str, password: str, timeout: float = 6.0) -> bool:
        """Verify using pty.fork() which explicitly configures the controlling terminal."""
        try:
            import pty
            import select
            import time
        except ImportError:
            return False

        su_binary = shutil.which("su") or "/bin/su"
        if not os.path.exists(su_binary):
            return False

        clean_pw = password.rstrip("\r\n")

        try:
            pid, master_fd = pty.fork()
        except Exception:
            return False

        if pid == 0:
            # Child process: pty.fork already called setsid() and redirected std streams to slave
            try:
                import fcntl
                import termios

                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            except Exception:
                pass

            env = {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
            }
            try:
                # IMPORTANT: options (-c "exit 0") MUST precede username.
                # Do NOT pass -s because shadow-utils su denies -s to non-root users.
                os.execve(su_binary, [su_binary, "-c", "exit 0", username], env)  # nosec B606
            except Exception:
                os._exit(127)

        # Parent process
        start_time = time.monotonic()
        password_sent = False
        collected_output: list[bytes] = []
        wnohang_flag = getattr(os, "WNOHANG", 1)

        try:
            while time.monotonic() - start_time < timeout:
                # 1. Non-blocking check for child exit
                waited_pid, status = os.waitpid(pid, wnohang_flag)
                if waited_pid == pid:
                    exit_code = (
                        os.waitstatus_to_exitcode(status)
                        if hasattr(os, "waitstatus_to_exitcode")
                        else (status >> 8)
                    )
                    return exit_code == 0

                # 2. Check for PTY activity
                r, _, _ = select.select([master_fd], [], [], 0.05)
                if r:
                    try:
                        data = os.read(master_fd, 1024)
                    except OSError:
                        # EIO indicates slave was closed when child terminated
                        data = b""

                    if data:
                        collected_output.append(data)
                        if not password_sent:
                            combined = b"".join(collected_output)
                            # When su prompts for password (e.g. "Password: ")
                            if b":" in combined or b"password" in combined.lower():
                                os.write(master_fd, (clean_pw + "\n").encode("utf-8"))
                                password_sent = True
                    else:
                        # Master FD gave EOF/EIO (slave closed because child exited)
                        # Wait for child to exit and return its exit code
                        try:
                            _, status = os.waitpid(pid, 0)
                            exit_code = (
                                os.waitstatus_to_exitcode(status)
                                if hasattr(os, "waitstatus_to_exitcode")
                                else (status >> 8)
                            )
                            return exit_code == 0
                        except Exception:
                            return False

                # 3. Fallback: if 2.5s passed and prompt was not detected, send password anyway
                if not password_sent and (time.monotonic() - start_time >= 2.5):
                    try:
                        os.write(master_fd, (clean_pw + "\n").encode("utf-8"))
                        password_sent = True
                    except OSError:
                        pass

            # Timeout reached: terminate child
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except Exception:
                pass
            return False

        finally:
            try:
                os.close(master_fd)
            except OSError:
                pass

    def _verify_via_su_pty(self, username: str, password: str, timeout: float = 6.0) -> bool:
        """Verify password by running su inside an openpty pair (fallback when fork is constrained)."""
        try:
            import pty
            import select
            import subprocess  # nosec B404
            import time
        except ImportError:
            return False

        su_binary = shutil.which("su") or "/bin/su"
        if not os.path.exists(su_binary):
            return False

        clean_pw = password.rstrip("\r\n")

        try:
            master_fd, slave_fd = pty.openpty()
        except Exception:
            return False

        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
        }

        try:
            proc = subprocess.Popen(  # nosec B603
                [su_binary, "-c", "exit 0", username],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                env=env,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )
        except Exception:
            os.close(master_fd)
            os.close(slave_fd)
            return False

        os.close(slave_fd)

        start_time = time.monotonic()
        password_sent = False
        collected_output: list[bytes] = []

        try:
            while time.monotonic() - start_time < timeout:
                if proc.poll() is not None:
                    break

                r, _, _ = select.select([master_fd], [], [], 0.05)
                if r:
                    try:
                        data = os.read(master_fd, 1024)
                    except OSError:
                        break

                    if not data:
                        break

                    collected_output.append(data)
                    if not password_sent:
                        combined = b"".join(collected_output)
                        if b":" in combined or b"password" in combined.lower():
                            try:
                                os.write(master_fd, (clean_pw + "\n").encode("utf-8"))
                                password_sent = True
                            except OSError:
                                break

                elif not password_sent and (time.monotonic() - start_time >= 2.5):
                    try:
                        os.write(master_fd, (clean_pw + "\n").encode("utf-8"))
                        password_sent = True
                    except OSError:
                        break

            rem_timeout = max(0.5, timeout - (time.monotonic() - start_time))
            try:
                return_code = proc.wait(timeout=rem_timeout)
                return return_code == 0
            except subprocess.TimeoutExpired:
                proc.kill()
                return False

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

    def _verify_via_libpam_ctypes(self, username: str, password: str, service: str = "common-auth") -> bool:
        """Authenticate user against Linux PAM in-process using ctypes bindings."""
        try:
            import ctypes
            import ctypes.util

            libpam_name = ctypes.util.find_library("pam") or "libpam.so.0"
            try:
                libpam = ctypes.CDLL(libpam_name)
            except OSError:
                libpam = ctypes.CDLL("libpam.so")
        except Exception:
            return False

        try:
            class PamHandle(ctypes.Structure):
                pass

            class PamMessage(ctypes.Structure):
                _fields_ = [
                    ("msg_style", ctypes.c_int),
                    ("msg", ctypes.c_char_p),
                ]

            class PamResponse(ctypes.Structure):
                _fields_ = [
                    ("resp", ctypes.c_void_p),
                    ("resp_retcode", ctypes.c_int),
                ]

            CMPFUNC = ctypes.CFUNCTYPE(
                ctypes.c_int,
                ctypes.c_int,
                ctypes.POINTER(ctypes.POINTER(PamMessage)),
                ctypes.POINTER(ctypes.POINTER(PamResponse)),
                ctypes.c_void_p,
            )

            class PamConv(ctypes.Structure):
                _fields_ = [
                    ("conv", CMPFUNC),
                    ("appdata_ptr", ctypes.c_void_p),
                ]

            libc = ctypes.CDLL(None)
            alloc = libc.calloc
            alloc.restype = ctypes.c_void_p
            strdup = libc.strdup
            strdup.restype = ctypes.c_void_p

            pw_bytes = password.rstrip("\r\n").encode("utf-8")

            @CMPFUNC
            def conv_callback(num_msg, msg, resp, appdata_ptr):
                resp_array = ctypes.cast(
                    alloc(num_msg, ctypes.sizeof(PamResponse)),
                    ctypes.POINTER(PamResponse),
                )
                for i in range(num_msg):
                    style = msg[i].contents.msg_style
                    if style == 1:  # PAM_PROMPT_ECHO_OFF
                        resp_array[i].resp = strdup(pw_bytes)
                        resp_array[i].resp_retcode = 0
                    else:
                        resp_array[i].resp = None
                        resp_array[i].resp_retcode = 0
                resp.contents = resp_array
                return 0

            pam_start = libpam.pam_start
            pam_start.restype = ctypes.c_int
            pam_start.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.POINTER(PamConv),
                ctypes.POINTER(ctypes.POINTER(PamHandle)),
            ]

            pam_authenticate = libpam.pam_authenticate
            pam_authenticate.restype = ctypes.c_int
            pam_authenticate.argtypes = [ctypes.POINTER(PamHandle), ctypes.c_int]

            pam_end = libpam.pam_end
            pam_end.restype = ctypes.c_int
            pam_end.argtypes = [ctypes.POINTER(PamHandle), ctypes.c_int]

            conv_struct = PamConv(conv_callback, None)
            handle = ctypes.POINTER(PamHandle)()

            svc_bytes = service.encode("utf-8")
            usr_bytes = username.encode("utf-8")

            res = pam_start(svc_bytes, usr_bytes, ctypes.byref(conv_struct), ctypes.byref(handle))
            if res != 0:
                return False

            auth_res = pam_authenticate(handle, 0)
            pam_end(handle, auth_res)
            return auth_res == 0
        except Exception:
            return False

    def _verify_via_sudo(self, username: str, password: str) -> bool:
        """Authenticate via sudo -k -S true (allows root validation with admin user's sudo password on Ubuntu)."""
        current_user = None
        try:
            import pwd

            current_user = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            pass

        # Sudo stdin password only validates the process user's password for root elevation
        if username != "root" and (current_user is None or username != current_user):
            return False

        sudo_binary = shutil.which("sudo")
        if not sudo_binary:
            return False

        import subprocess  # nosec B404

        clean_pw = password.rstrip("\r\n")
        cmd = [sudo_binary, "-k", "-S", "true"]
        try:
            res = subprocess.run(  # nosec B603
                cmd,
                input=(clean_pw + "\n").encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5.0,
            )
            return res.returncode == 0
        except Exception:
            return False
