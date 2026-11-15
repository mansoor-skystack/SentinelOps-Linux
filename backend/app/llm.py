import os
import json
from typing import List, Dict, Any
from groq import Groq
from .guardrails import CommandSafetyGuardrail

SYSTEM_PROMPT = """You are SentinelOps, a Senior Linux & Cloud Site Reliability Engineer (SRE) Copilot.
Analyze the sanitized error log strictly using the retrieved runbook context below.
If the input is completely unrelated to Linux, servers, containers, databases, or cloud operations, set "out_of_scope": true.

Return strictly valid JSON matching this schema:
{
  "out_of_scope": false,
  "root_cause": "Clear technical explanation grounded in the retrieved documentation.",
  "diagnostic_commands": ["command 1", "command 2"],
  "fix_commands": ["remediation command 1"],
  "citations": ["[Source: filename.md, Section]"]
}
"""

def synthesize_diagnosis(sanitized_log: str, chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
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
        fallback_diag = ["journalctl -p err -n 30 --no-pager", "df -h && free -m"]
        fallback_fix = ["sudo systemctl restart nginx.service"]
        for line in top_text.splitlines():
            if line.startswith("Fix:"):
                fallback_fix = [line.replace("Fix:", "").strip()]
        risk, flagged = CommandSafetyGuardrail.inspect(fallback_fix)
        return {
            "out_of_scope": False,
            "root_cause": f"[Offline Retrieval Mode — Add your SentinelOps GROQ_API_KEY in .env for Llama-3.3-70B synthesis] Top matched runbook guidance: {top_text[:320]}...",
            "diagnostic_commands": fallback_diag,
            "fix_commands": fallback_fix,
            "citations": unique_citations,
            "risk_level": risk,
            "flagged_commands": flagged
        }

    client = Groq(api_key=api_key)
    prompt = f"### Retrieved Runbook Context:\n{context_str}\n\n### Sanitized Linux Error Log:\n```\n{sanitized_log}\n```"
    completion = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        temperature=0.1,
        response_format={"type": "json_object"}
    )
    parsed = json.loads(completion.choices[0].message.content)
    fix_cmds = parsed.get("fix_commands", [])
    risk, flagged = CommandSafetyGuardrail.inspect(fix_cmds)
    parsed["risk_level"] = risk
    parsed["flagged_commands"] = flagged
    if not parsed.get("citations"):
        parsed["citations"] = unique_citations
    return parsed
