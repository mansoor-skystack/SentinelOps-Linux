import re
from typing import List, Tuple

class CommandSafetyGuardrail:
    """Deterministic rule-based filter flagging destructive Linux/DevOps shell commands."""

    DANGEROUS_PATTERNS = [
        re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-rf\b"),
        re.compile(r"\bchmod\s+777\b"),
        re.compile(r"\bmkfs\."),
        re.compile(r"\bdd\s+if="),
        re.compile(r"\bkill\s+-9\b"),
        re.compile(r"\biptables\s+-F\b"),
        re.compile(r"\bsystemctl\s+(stop|mask)\s+(sshd|networking|systemd)"),
    ]

    @classmethod
    def inspect(cls, commands: List[str]) -> Tuple[str, List[str]]:
        flagged = []
        for cmd in commands:
            for pat in cls.DANGEROUS_PATTERNS:
                if pat.search(cmd):
                    flagged.append(cmd)
                    break
        return ("HIGH_RISK" if flagged else "SAFE"), flagged
