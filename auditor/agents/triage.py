"""TriageAgent: dedupe Slither findings and add business-logic candidates."""

from __future__ import annotations

import logging

from auditor.agents.llm import structured_invoke
from auditor.config import get_settings
from auditor.models import (
    Candidate,
    FetchedContract,
    Severity,
    SlitherFinding,
    TriageCandidateSchema,
    TriageOutputSchema,
)
from auditor.util import contract_source_bundle, slugify

logger = logging.getLogger(__name__)

_SYSTEM = """You are a senior Ethereum smart-contract security auditor performing a FIRST-PASS review.

This is a DEFENSIVE audit. Your job is to identify real vulnerabilities and propose remediation.
You must NOT provide advice for attacking live systems.

You receive:
1. Verified Solidity source (proxy and/or implementation)
2. Parsed Slither static-analysis findings (may be empty if Slither failed)

Produce a DEDUPLICATED list of candidate vulnerabilities.

Rules:
- Merge overlapping Slither detectors into a single candidate when they describe the same bug.
- Keep genuine High/Critical Slither issues even if they look noisy, but drop Informational/optimization noise unless it enables a real exploit.
- ADD business-logic flaws Slither cannot catch: broken access control, missing invariants, oracle/price manipulation, accounting errors, incorrect settlement math, privilege escalation, uninitialized proxies, signature replay, and griefing that drains value.
- Assign severity: Critical (direct theft / frozen funds of significant TVL), High (theft with constraints or serious accounting break), Medium (limited impact or hard preconditions), Low (best-practice / unproven).
- If the source looks like a well-known token/proxy with no obvious bug, it is acceptable to return an empty candidate list or only Low items. Do not invent issues.
- Every candidate needs concrete remediation guidance a maintainer can apply.
"""

class TriageAgent:
    """LCEL structured-output chain that turns source + Slither into candidates."""

    def run(
        self,
        contract: FetchedContract,
        slither_findings: list[SlitherFinding],
        slither_error: str | None = None,
    ) -> tuple[str, list[Candidate], dict[str, str]]:
        """Return (summary, candidates, remediation_by_id)."""
        settings = get_settings()
        source = contract_source_bundle(contract, settings.llm_source_char_limit)
        slither_text = _format_slither(slither_findings, slither_error)

        logger.info("TriageAgent invoking LLM (%s findings from Slither)", len(slither_findings))
        human = (
            f"Contract address: {contract.address}\n"
            f"Contract name: {contract.name}\n"
            f"Is proxy: {contract.is_proxy}\n"
            f"Implementation address: {contract.implementation_address or 'n/a'}\n"
            f"Compiler: {contract.compiler_version}\n\n"
            f"Slither findings (JSON-ish text):\n{slither_text}\n\n"
            f"Source:\n{source}\n"
        )
        try:
            output = structured_invoke(
                TriageOutputSchema,
                system=_SYSTEM,
                human=human,
            )
        except Exception:
            logger.exception("TriageAgent LLM call failed; falling back to Slither-only candidates")
            return _fallback(slither_findings)

        remediations: dict[str, str] = {}
        candidates: list[Candidate] = []
        for index, item in enumerate(output.candidates, start=1):
            candidate = _from_schema(item, index)
            candidates.append(candidate)
            remediations[candidate.id] = item.remediation
        logger.info("TriageAgent produced %s candidate(s)", len(candidates))
        return output.summary, candidates, remediations


def _from_schema(item: TriageCandidateSchema, index: int) -> Candidate:
    return Candidate(
        id=slugify(item.title, index),
        title=item.title.strip(),
        severity=Severity(item.severity),
        rationale=item.rationale.strip(),
        category=item.category.strip(),
        target_functions=item.target_functions,
        related_slither_checks=item.related_slither_checks,
    )


def _format_slither(findings: list[SlitherFinding], error: str | None) -> str:
    if error:
        header = f"Slither failed or ran degraded:\n{error[:2000]}\n\n"
    else:
        header = ""
    if not findings:
        return header + "(no Slither detector findings)"
    lines: list[str] = [header] if header else []
    for finding in findings:
        loc = ""
        if finding.filenames or finding.lines:
            loc = f" @ {', '.join(finding.filenames[:3])} lines={finding.lines[:8]}"
        lines.append(
            f"- [{finding.impact}/{finding.confidence}] {finding.check}{loc}: "
            f"{finding.description[:500]}"
        )
    return "\n".join(lines)


def _fallback(findings: list[SlitherFinding]) -> tuple[str, list[Candidate], dict[str, str]]:
    severity_map = {
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.LOW,
        "optimization": Severity.LOW,
        "critical": Severity.CRITICAL,
    }
    candidates: list[Candidate] = []
    remediations: dict[str, str] = {}
    for index, finding in enumerate(findings, start=1):
        sev = severity_map.get(finding.impact.lower(), Severity.MEDIUM)
        if finding.impact.lower() in {"informational", "optimization"}:
            continue
        candidate = Candidate(
            id=slugify(finding.check, index),
            title=finding.check,
            severity=sev,
            rationale=finding.description[:800] or "Imported from Slither after LLM triage failed.",
            category="static",
            related_slither_checks=[finding.check],
        )
        candidates.append(candidate)
        remediations[candidate.id] = "Review the Slither detector documentation and apply the recommended fix."
    summary = "Triage LLM failed; candidates were derived from Slither only."
    return summary, candidates, remediations
