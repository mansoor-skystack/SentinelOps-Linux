import re
from typing import Tuple, Dict

class LogSanitizer:
    """Filters noisy INFO/DEBUG lines and masks IPv4 addresses, API keys, passwords, and SSH keys."""

    NOISE_PATTERN = re.compile(r"(?i)^.*\b(INFO|DEBUG|TRACE)\b.*$", re.MULTILINE)

    PII_PATTERNS = [
        ("IPV4", re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"), "[REDACTED_IP]"),
        ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
        ("BEARER_TOKEN", re.compile(r"(?i)Bearer\s+[a-zA-Z0-9_\-\.=]+"), "Bearer [REDACTED_TOKEN]"),
        ("SECRET_ASSIGNMENT", re.compile(r"(?i)(password|passwd|secret|api_key|token)\s*[:=]\s*['\"]?[^\s'\"]+['\"]?"), r"\1=[REDACTED_SECRET]"),
        ("SSH_PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----"), "[REDACTED_SSH_KEY]"),
    ]

    @classmethod
    def filter_and_sanitize(cls, raw_log: str) -> Tuple[str, Dict[str, int], int]:
        lines = raw_log.splitlines()
        filtered_lines = [ln for ln in lines if ln.strip() and not cls.NOISE_PATTERN.match(ln)]
        dropped_count = len(lines) - len(filtered_lines)
        cleaned = "\n".join(filtered_lines) if filtered_lines else raw_log.strip()

        redactions: Dict[str, int] = {}
        for label, pattern, replacement in cls.PII_PATTERNS:
            cleaned, count = pattern.subn(replacement, cleaned)
            if count > 0:
                redactions[label] = count

        return cleaned, redactions, dropped_count
