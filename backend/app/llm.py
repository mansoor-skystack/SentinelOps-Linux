import os
import json
import logging
import re
from typing import List, Dict, Any, Optional
from groq import APIError, Groq
from .guardrails import CommandSafetyGuardrail

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are SentinelOps, a Senior Linux & Cloud Site Reliability Engineer (SRE) Copilot.
Analyze the sanitized error log strictly using the retrieved runbook context below.
If the input is completely unrelated to Linux, servers, containers, databases, or cloud operations, set "out_of_scope": true.
Use collector telemetry as supporting evidence, not proof. CPU load is a one-minute load average, not a CPU percentage. Distinguish host memory pressure from a container cgroup limit only when the logs or runbook provide evidence; otherwise state that the limit is unknown.

Return strictly valid JSON matching this schema:
{
  "out_of_scope": false,
  "root_cause": "Clear technical explanation grounded in the retrieved documentation.",
  "diagnostic_commands": ["command 1", "command 2"],
  "fix_commands": ["remediation command 1"],
  "citations": ["[Source: filename.md, Section]"]
}
"""

def _extract_fix_commands(runbook_text: str) -> List[str]:
    commands = []
    in_fix_section = False
    in_code_block = False

    for line in runbook_text.splitlines():
        stripped = line.strip()
        heading = re.match(r"^#{1,6}\s+(.+)$", stripped)
        if heading:
            title = heading.group(1).strip().rstrip(":").lower()
            in_fix_section = title in {"fix", "resolution"}
            in_code_block = False
            continue

        if re.match(r"^(?:fix|resolution)\s*:", stripped, re.IGNORECASE):
            in_fix_section = True
            inline = re.sub(r"^(?:fix|resolution)\s*:\s*", "", stripped, flags=re.IGNORECASE)
            if inline:
                commands.append(inline.strip("` "))
            continue
        if not in_fix_section:
            continue

        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            if stripped:
                commands.append(stripped)
            continue

        bullet = re.match(r"^(?:[-*+]|\d+[.)])\s+(.+)$", stripped)
        if bullet:
            command = bullet.group(1).strip().strip("` ")
            if command:
                commands.append(command)

    return list(dict.fromkeys(command for command in commands if command))

def synthesize_diagnosis(
    sanitized_log: str,
    chunks: List[Dict[str, Any]],
    telemetry: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    citations = []
    context_parts = []
    for c in chunks:
        cite = f"[Source: {c['meta']['source']}, {c['meta']['section']}]"
        citations.append(cite)
        context_parts.append(f"{cite}\n{c['text']}")

    unique_citations = list(dict.fromkeys(citations))
    context_str = "\n---\n".join(context_parts) if context_parts else "No runbook matched."

    if not api_key or api_key.startswith("gsk_your_"):
        top_text = chunks[0]["text"] if chunks else "No matching runbook found."
        runbook_text = "\n\n".join(chunk["text"] for chunk in chunks)
        fallback_diag = ["journalctl -p err -n 30 --no-pager", "df -h && free -m"]
        fallback_fix = _extract_fix_commands(runbook_text)
        risk, flagged = CommandSafetyGuardrail.inspect(fallback_fix)
        return {
            "out_of_scope": False,
            "root_cause": f"[Offline Retrieval Mode — Configure GROQ_API_KEY for model-backed synthesis] Top matched runbook guidance: {top_text[:320]}...",
            "diagnostic_commands": fallback_diag,
            "fix_commands": fallback_fix,
            "citations": unique_citations,
            "risk_level": risk,
            "flagged_commands": flagged
        }

    telemetry_context = (
        "### Collector Host Telemetry\n"
        f"{json.dumps(telemetry, sort_keys=True)}\n"
        "cpu_load is a one-minute load average; mem_used_pct and disk_used_pct are percentages."
        if telemetry is not None
        else "### Collector Host Telemetry\nUnavailable for this diagnosis; do not infer host metrics."
    )
    prompt = (
        f"### Retrieved Runbook Context:\n{context_str}\n\n"
        f"{telemetry_context}\n\n"
        f"### Sanitized Linux Error Log:\n```\n{sanitized_log}\n```"
    )
    model = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b").strip()
    if not model:
        raise RuntimeError("GROQ_MODEL must not be empty")
    try:
        client = Groq(api_key=api_key)
        completion = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            response_format={"type": "json_object"}
        )
    except APIError as exc:
        logger.exception("Groq diagnosis request failed")
        raise RuntimeError("The configured Groq diagnosis request failed") from exc
    except TypeError as exc:
        logger.exception("Groq diagnosis client could not be initialized")
        raise RuntimeError("Unable to initialize the configured Groq diagnosis client") from exc

    try:
        parsed = json.loads(completion.choices[0].message.content)
    except (AttributeError, IndexError, TypeError, json.JSONDecodeError) as exc:
        logger.exception("Groq returned an invalid diagnosis response")
        raise RuntimeError("Groq returned an invalid diagnosis response") from exc
    fix_cmds = parsed.get("fix_commands", [])
    risk, flagged = CommandSafetyGuardrail.inspect(fix_cmds)
    parsed["risk_level"] = risk
    parsed["flagged_commands"] = flagged
    if not parsed.get("citations"):
        parsed["citations"] = unique_citations
    return parsed
