"""ReportAgent: compile the markdown audit report."""

from __future__ import annotations

import logging

from auditor.agents.llm import structured_invoke
from auditor.models import AuditResult, FindingStatus, ReportOutputSchema

logger = logging.getLogger(__name__)

_SYSTEM = """You are writing a professional smart-contract audit report.

This is a DEFENSIVE, automated first-pass tool. Frame everything as findings + remediation.
Never frame results as an attack playbook.

The report MUST be valid markdown with these sections in order:
1. Title and metadata (address, name, fork block, proxy/implementation if any)
2. Disclaimer (verbatim spirit): this is an automated first-pass; CONFIRMED findings still need human review; PoCs ran only on a local Foundry mainnet fork and never touched the live chain.
3. Executive summary (counts by severity and by status: CONFIRMED via PoC / unconfirmed / static-only)
4. Findings, each with: title, severity, status, rationale, remediation, and — only for CONFIRMED — the passing PoC Solidity in a ```solidity fence
5. Methodology (fetch verified source → Slither → LLM triage → Foundry fork PoC)

Be precise:
- List ONLY the findings in the input JSON `findings` array. Do not add Informational
  or other issues from Slither that were not triaged into that array.
- Do not upgrade unconfirmed or static-only issues to confirmed.
- For each UNCONFIRMED Critical/High finding, include the last PoC forge error
  (`attempts[-1].revert_reason`) so a reviewer can see why confirmation failed.
- For CONFIRMED findings, include the passing PoC Solidity in a ```solidity fence.
"""

class ReportAgent:
    """LCEL chain that turns AuditResult into markdown. Falls back to a template."""

    def run(self, result: AuditResult) -> str:
        payload = result.model_dump(mode="json")
        # PoC source can be large; keep attempts truncated for the prompt.
        for finding in payload.get("findings", []):
            attempts = finding.get("attempts") or []
            for attempt in attempts:
                attempt["stdout"] = (attempt.get("stdout") or "")[-500:]
                attempt["stderr"] = (attempt.get("stderr") or "")[-500:]
        logger.info("ReportAgent compiling markdown for %s", result.address)
        try:
            output = structured_invoke(
                ReportOutputSchema,
                system=_SYSTEM,
                human=(
                    "Produce the report from this structured audit result (JSON):\n\n"
                    f"{_json(payload)}\n"
                ),
            )
            markdown = output.markdown.strip()
            if markdown:
                return markdown
        except Exception:
            logger.exception("ReportAgent LLM failed; using template report")
        return render_template_report(result)


def render_template_report(result: AuditResult) -> str:
    """Deterministic markdown if the LLM is unavailable."""
    confirmed = sum(1 for f in result.findings if f.status is FindingStatus.CONFIRMED)
    unconfirmed = sum(1 for f in result.findings if f.status is FindingStatus.UNCONFIRMED)
    static_only = sum(1 for f in result.findings if f.status is FindingStatus.STATIC_ONLY)
    fork = result.fork_block if result.fork_block is not None else "latest"

    lines = [
        f"# Audit report: {result.contract_name}",
        "",
        f"- **Address:** `{result.address}`",
        f"- **Fork block:** {fork}",
        f"- **Proxy:** {'yes' if result.is_proxy else 'no'}",
    ]
    if result.implementation_address:
        lines.append(f"- **Implementation:** `{result.implementation_address}`")
    if result.proxy_hint:
        lines.append(f"- **Proxy notes:** {result.proxy_hint}")
    lines += [
        "",
        "## Disclaimer",
        "",
        "This is an **automated first-pass** audit. Confirmed findings were proven only by a",
        "Foundry test running against a **local mainnet fork** — nothing was sent to the live chain.",
        "A passing PoC is strong evidence but still requires human review before any production action.",
        "",
        "## Executive summary",
        "",
        f"- Findings: **{len(result.findings)}** "
        f"(CONFIRMED via PoC: {confirmed}, unconfirmed: {unconfirmed}, static-only: {static_only})",
        f"- Slither detectors parsed: {len(result.slither_findings)}",
    ]
    if result.slither_error:
        lines.append(f"- Slither ran in degraded mode: `{result.slither_error[:300]}`")
    lines += ["", "## Findings", ""]

    if not result.findings:
        lines.append("No candidate vulnerabilities were triaged.")
    for finding in result.findings:
        c = finding.candidate
        lines += [
            f"### {c.severity.value}: {c.title}",
            "",
            f"- **Status:** {finding.status_label}",
            f"- **Category:** {c.category or 'n/a'}",
            f"- **Functions:** {', '.join(c.target_functions) or 'n/a'}",
            "",
            c.rationale,
            "",
        ]
        if finding.remediation:
            lines += ["**Remediation**", "", finding.remediation, ""]
        if finding.status is FindingStatus.CONFIRMED and finding.poc_code:
            lines += ["**Passing PoC**", "", "```solidity", finding.poc_code.strip(), "```", ""]
        elif finding.attempts:
            last = finding.attempts[-1]
            reason = last.revert_reason or "test did not pass"
            lines += [f"PoC did not confirm (after {len(finding.attempts)} attempt(s)): `{reason[:400]}`", ""]

    lines += [
        "## Methodology",
        "",
        "1. Fetch verified source from Etherscan (follow EIP-1967 implementation if this is a proxy).",
        "2. Static analysis with Slither at the matching solc version.",
        "3. LLM triage for business-logic issues Slither cannot see.",
        "4. For each Critical/High candidate, generate a Foundry fork test and retry on failure.",
        "5. Mark CONFIRMED only when the PoC test passes.",
        "",
    ]
    return "\n".join(lines)


def _json(payload: dict) -> str:
    import json

    return json.dumps(payload, indent=2, default=str)
