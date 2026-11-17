import re
from typing import Dict, Tuple


class LogSanitizer:
    """Filters noisy lines and masks common secrets and public IPv4 addresses."""

    NOISE_PATTERN = re.compile(r"(?i)^.*\b(INFO|DEBUG|TRACE)\b.*$", re.MULTILINE)

    PII_PATTERNS = [
        ("URL_CREDENTIALS", re.compile(r"(?i)(://[^:/@\s]+:)[^/@\s]+@"), r"\1[REDACTED_SECRET]@"),
        (
            "IPV4",
            re.compile(
                r"\b(?!(?:127\.0\.0\.1|0\.0\.0\.0)\b)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
            "[REDACTED_IP]",
        ),
        ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
        ("BEARER_TOKEN", re.compile(r"(?i)Bearer\s+[a-zA-Z0-9_\-\.=]+"), "Bearer [REDACTED_TOKEN]"),
        (
            "SECRET_ASSIGNMENT",
            re.compile(r"(?i)(password|passwd|secret|api_key|token)\s*[:=]\s*['\"]?[^\s'\"]+['\"]?"),
            r"\1=[REDACTED_SECRET]",
        ),
        (
            "SSH_PRIVATE_KEY",
            re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----"),
            "[REDACTED_SSH_KEY]",
        ),
    ]

    @classmethod
    def filter_and_sanitize(cls, raw_log: str) -> Tuple[str, Dict[str, int], int]:
        lines = raw_log.splitlines()
        filtered_lines = [line for line in lines if line.strip() and not cls.NOISE_PATTERN.match(line)]
        dropped_count = len(lines) - len(filtered_lines)
        cleaned = "\n".join(filtered_lines) if filtered_lines else raw_log.strip()

        redactions: Dict[str, int] = {}
        for label, pattern, replacement in cls.PII_PATTERNS:
            cleaned, count = pattern.subn(replacement, cleaned)
            if count > 0:
                redactions[label] = count

        return cleaned, redactions, dropped_count
