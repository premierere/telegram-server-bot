"""Policy engine for restricted mode and dangerous pattern speed bump detection.

In restricted mode:
- Exact argv vector execution with asyncio.create_subprocess_exec (NO shell).
- Every argument is validated strictly against an enum or a regex.
- Command injection characters (pipes, semicolons, $(), ../, etc.) are inert or rejected.

In shell mode:
- Dangerous patterns trigger a mandatory interactive confirmation prompt with nonce and hash.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from src.config import ConfigurationError

# Common dangerous command patterns (speed bump for shell mode)
DEFAULT_DANGEROUS_PATTERNS = [
    r"\brm\s+.*(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)\b",
    r"\bmkfs(\.[a-zA-Z0-9_-]+)?\b",
    r"\bdd\s+.*of=/dev/",
    r"\b(shutdown|reboot|poweroff|halt|init\s+[06])\b",
    r"\b(passwd|useradd|userdel|usermod|groupadd|groupdel|visudo)\b",
    r"\bchmod\s+(-[a-zA-Z]*R[a-zA-Z]*\s+)?(777|a\+rwx)\b",
    r"\bchown\s+(-[a-zA-Z]*R[a-zA-Z]*\s+)?(root|0)\b",
    r"\b(iptables\s+-F|ufw\s+disable|nft\s+flush)\b",
    r"\b(curl|wget)\s+.*\|\s*(bash|sh|zsh)\b",
    r":\(\)\s*\{\s*:\|:&\s*\};:",  # Fork bomb
]


@dataclass(frozen=True)
class ParamValidation:
    """Parameter validation rules."""

    enum: list[str] | None = None
    regex: str | None = None


@dataclass(frozen=True)
class PolicyEntry:
    """A single authorized command template in restricted mode."""

    name: str
    argv: list[str]
    params: dict[str, ParamValidation] = field(default_factory=dict)
    description: str = ""


class PolicyEngine:
    """Loads policy.yaml and validates restricted commands and dangerous shell commands."""

    def __init__(
        self,
        policy_path: str | Path | None = None,
        custom_dangerous_patterns: list[str] | None = None,
    ) -> None:
        self.commands: dict[str, PolicyEntry] = {}
        patterns = custom_dangerous_patterns or DEFAULT_DANGEROUS_PATTERNS
        self._dangerous_regexes = [re.compile(p, re.IGNORECASE) for p in patterns]

        if policy_path is not None:
            self.load_policy(policy_path)

    def load_policy(self, policy_path: str | Path) -> None:
        """Parse and validate policy.yaml."""
        p = Path(policy_path)
        if not p.is_file():
            raise ConfigurationError(f"Policy file not found: {p}")

        try:
            content = p.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
        except Exception as exc:
            raise ConfigurationError(f"Failed to parse policy YAML: {exc}") from exc

        if not isinstance(data, dict) or "commands" not in data:
            raise ConfigurationError("Policy YAML must have a top-level 'commands' list.")

        raw_commands = data.get("commands")
        if not isinstance(raw_commands, list):
            raise ConfigurationError("'commands' in policy YAML must be a list.")

        commands: dict[str, PolicyEntry] = {}
        for item in raw_commands:
            if not isinstance(item, dict):
                raise ConfigurationError("Each command entry in policy must be a mapping.")

            name = item.get("name")
            argv = item.get("argv")
            if not name or not isinstance(name, str):
                raise ConfigurationError("Each command entry must have a string 'name'.")
            if not argv or not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
                raise ConfigurationError(f"Command '{name}' must have a non-empty list of string 'argv'.")

            # Validate parameters schema
            raw_params = item.get("params", {})
            if not isinstance(raw_params, dict):
                raise ConfigurationError(f"Params for command '{name}' must be a mapping.")

            params: dict[str, ParamValidation] = {}
            for param_name, rule in raw_params.items():
                if not isinstance(param_name, str) or not isinstance(rule, dict):
                    raise ConfigurationError(f"Invalid param rule for '{param_name}' in command '{name}'.")

                enum_vals = rule.get("enum")
                regex_val = rule.get("regex")

                if enum_vals is not None and (not isinstance(enum_vals, list) or not all(isinstance(e, str) for e in enum_vals)):
                    raise ConfigurationError(f"enum in param '{param_name}' of command '{name}' must be a list of strings.")

                if regex_val is not None and not isinstance(regex_val, str):
                    raise ConfigurationError(f"regex in param '{param_name}' of command '{name}' must be a string.")

                if enum_vals is None and regex_val is None:
                    raise ConfigurationError(f"Param '{param_name}' of command '{name}' must specify either 'enum' or 'regex'.")

                params[param_name] = ParamValidation(enum=enum_vals, regex=regex_val)

            commands[name] = PolicyEntry(
                name=name,
                argv=argv,
                params=params,
                description=str(item.get("description", "")),
            )

        self.commands = commands

    def is_dangerous_shell_command(self, command_str: str) -> bool:
        """Check if command matches any dangerous shell patterns."""
        normalized = command_str.strip()
        for regex in self._dangerous_regexes:
            if regex.search(normalized):
                return True
        return False

    def validate_and_build_argv(
        self,
        command_name: str,
        supplied_args: list[str],
    ) -> tuple[bool, list[str] | None, str]:
        """Validate supplied arguments against policy entry and build safe argv vector.

        Returns:
            (success, resolved_argv, reason)
        """
        entry = self.commands.get(command_name)
        if not entry:
            return False, None, "command_not_found"

        # Determine expected parameters from argv templates (e.g., "{unit}", "{path}")
        placeholders: list[str] = []
        for token in entry.argv:
            found = re.findall(r"\{([a-zA-Z0-9_]+)\}", token)
            placeholders.extend(found)

        # Remove duplicates while preserving order
        unique_placeholders = list(dict.fromkeys(placeholders))

        if len(supplied_args) != len(unique_placeholders):
            return (
                False,
                None,
                f"argument_count_mismatch: expected {len(unique_placeholders)}, got {len(supplied_args)}",
            )

        # Map supplied arguments to placeholder names
        param_values = dict(zip(unique_placeholders, supplied_args))

        # Validate each supplied parameter against its validation rules
        for p_name, p_val in param_values.items():
            rule = entry.params.get(p_name)
            if not rule:
                return False, None, f"unconfigured_parameter_validation: {p_name}"

            # Check enum
            if rule.enum is not None and p_val not in rule.enum:
                return False, None, f"enum_validation_failed for '{p_name}': '{p_val}' not in allowed list"

            # Check regex
            if rule.regex is not None:
                pattern = f"^{rule.regex.lstrip('^').rstrip('$')}$"
                if not re.match(pattern, p_val):
                    return False, None, f"regex_validation_failed for '{p_name}': '{p_val}' does not match pattern"

        # Interpolate validated parameters into argv template
        resolved_argv: list[str] = []
        for token in entry.argv:
            interpolated = token
            for p_name, p_val in param_values.items():
                interpolated = interpolated.replace(f"{{{p_name}}}", p_val)
            resolved_argv.append(interpolated)

        return True, resolved_argv, "ok"
