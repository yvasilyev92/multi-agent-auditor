"""Sequential pipeline that wires tools and LCEL agents together."""

from __future__ import annotations

import logging
import tempfile
from collections.abc import Callable
from pathlib import Path

from auditor.agents.exploit import ExploitAgent
from auditor.agents.report import ReportAgent, render_template_report
from auditor.agents.triage import TriageAgent
from auditor.config import STAGE_LABELS, get_settings
from auditor.errors import AuditorError
from auditor.models import (
    AuditResult,
    Candidate,
    ExploitAttempt,
    FetchedContract,
    Finding,
    FindingStatus,
    Severity,
)
from auditor.tools.fetcher import FetcherTool
from auditor.tools.forge_runner import ForgeRunnerTool
from auditor.tools.static_analysis import StaticAnalysisTool
from auditor.util import checksum_solidity_addresses, validate_address

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, str, str], None]

_POC_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}


def run_audit(
    address: str,
    fork_block: int | None = None,
    on_progress: ProgressCallback | None = None,
    *,
    fork_url: str | None = None,
    local_source_dir: str | Path | None = None,
) -> AuditResult:
    """Run the full audit pipeline. Raises ``AuditorError`` for user-facing failures.

    ``local_source_dir`` skips Etherscan and loads Solidity from disk (fixture eval).
    ``fork_url`` overrides the RPC used for Foundry PoCs (Anvil when testing fixtures).
    """
    settings = get_settings()
    settings.require_secrets(etherscan=local_source_dir is None)
    checksum = validate_address(address)
    block = fork_block if fork_block is not None else settings.default_fork_block

    fetcher = FetcherTool()
    static_tool = StaticAnalysisTool()
    triage_agent = TriageAgent()
    exploit_agent = ExploitAgent()
    forge_tool = ForgeRunnerTool()
    report_agent = ReportAgent()

    def emit(stage: str, status: str, detail: str = "") -> None:
        logger.info("stage=%s status=%s %s", stage, status, detail)
        if on_progress:
            on_progress(stage, status, detail)

    with tempfile.TemporaryDirectory(prefix="auditor-") as tmp:
        workdir = Path(tmp)

        if local_source_dir is not None:
            emit("fetching", "running", f"Loading local source for {checksum}")
            try:
                contract = fetcher.load_local(
                    checksum, local_source_dir, workdir / "local"
                )
            except AuditorError as exc:
                emit("fetching", "error", str(exc))
                raise
        else:
            emit("fetching", "running", f"Fetching verified source for {checksum}")
            try:
                contract = fetcher.fetch(checksum, workdir, fork_block=block)
            except AuditorError as exc:
                emit("fetching", "error", str(exc))
                raise
        extra = ""
        if contract.is_proxy and contract.implementation_address:
            extra = f" (proxy → {contract.implementation_address})"
        emit(
            "fetching",
            "done",
            f"{contract.name} · {len(contract.source_files)} file(s){extra}",
        )

        emit("static_analysis", "running", "Selecting solc and running Slither")
        static = static_tool.analyze(contract)
        if static.error:
            emit(
                "static_analysis",
                "done",
                f"Slither degraded ({len(static.findings)} findings). {static.error[:180]}",
            )
        else:
            emit("static_analysis", "done", f"{len(static.findings)} Slither finding(s)")

        emit("triage", "running", "LLM triage of source + static findings")
        try:
            _summary, candidates, remediations = triage_agent.run(
                contract, static.findings, static.error
            )
        except Exception as exc:
            emit("triage", "error", str(exc))
            raise AuditorError(f"Triage agent failed: {exc}") from exc
        emit("triage", "done", f"{len(candidates)} candidate(s)")

        emit("exploit_confirmation", "running", "Generating Foundry PoCs for Critical/High")
        findings = _confirm_candidates(
            contract=contract,
            candidates=candidates,
            remediations=remediations,
            fork_block=block,
            fork_url=fork_url,
            exploit_agent=exploit_agent,
            forge_tool=forge_tool,
            workdir=workdir,
            emit=emit,
        )
        confirmed = sum(1 for f in findings if f.status is FindingStatus.CONFIRMED)
        emit(
            "exploit_confirmation",
            "done",
            f"{confirmed} confirmed of {sum(1 for c in candidates if c.severity in _POC_SEVERITIES)} Critical/High",
        )

        result = AuditResult(
            address=contract.address,
            contract_name=contract.name,
            fork_block=block,
            is_proxy=contract.is_proxy,
            implementation_address=contract.implementation_address,
            proxy_hint=contract.proxy_hint,
            slither_findings=static.findings,
            slither_error=static.error,
            findings=findings,
            source_file_count=_source_count(contract),
        )

        emit("report", "running", "Compiling markdown audit report")
        try:
            result.report_markdown = report_agent.run(result)
        except Exception:
            logger.exception("Report agent failed; using template")
            result.report_markdown = render_template_report(result)
        emit("report", "done", "Report ready")
        return result


def _confirm_candidates(
    *,
    contract: FetchedContract,
    candidates: list[Candidate],
    remediations: dict[str, str],
    fork_block: int | None,
    fork_url: str | None,
    exploit_agent: ExploitAgent,
    forge_tool: ForgeRunnerTool,
    workdir: Path,
    emit: ProgressCallback,
) -> list[Finding]:
    settings = get_settings()
    findings: list[Finding] = []
    poc_targets = [c for c in candidates if c.severity in _POC_SEVERITIES]
    skipped = [c for c in candidates if c.severity not in _POC_SEVERITIES]

    for index, candidate in enumerate(poc_targets, start=1):
        emit(
            "exploit_confirmation",
            "running",
            f"PoC {index}/{len(poc_targets)}: {candidate.title} ({candidate.severity.value})",
        )
        finding = _confirm_one(
            contract=contract,
            candidate=candidate,
            remediation=remediations.get(candidate.id, ""),
            fork_block=fork_block,
            fork_url=fork_url,
            exploit_agent=exploit_agent,
            forge_tool=forge_tool,
            workdir=workdir,
            max_attempts=settings.max_retries,
        )
        findings.append(finding)

    for candidate in skipped:
        findings.append(
            Finding(
                candidate=candidate,
                status=FindingStatus.STATIC_ONLY,
                remediation=remediations.get(candidate.id, ""),
            )
        )
    return findings


def _confirm_one(
    *,
    contract: FetchedContract,
    candidate: Candidate,
    remediation: str,
    fork_block: int | None,
    fork_url: str | None,
    exploit_agent: ExploitAgent,
    forge_tool: ForgeRunnerTool,
    workdir: Path,
    max_attempts: int,
) -> Finding:
    attempts: list[ExploitAttempt] = []
    previous_code = ""
    last_error = ""

    for attempt_no in range(1, max_attempts + 1):
        try:
            if attempt_no == 1:
                generated = exploit_agent.generate(
                    contract, candidate, fork_block=fork_block, fork_url=fork_url
                )
            else:
                generated = exploit_agent.revise(
                    contract,
                    candidate,
                    fork_block=fork_block,
                    previous_test=previous_code,
                    forge_error=last_error,
                    fork_url=fork_url,
                )
        except Exception as exc:
            logger.exception("ExploitAgent failed on attempt %s for %s", attempt_no, candidate.id)
            attempts.append(
                ExploitAttempt(
                    attempt=attempt_no,
                    test_code=previous_code,
                    passed=False,
                    revert_reason=f"ExploitAgent error: {exc}",
                )
            )
            last_error = str(exc)
            logger.info(
                "PoC attempt %s/%s for %s: compile_error=False reason=%s",
                attempt_no,
                max_attempts,
                candidate.id,
                last_error[:400],
            )
            continue

        test_code = checksum_solidity_addresses(strip_code_fences(generated.test_code))
        previous_code = test_code
        if not test_code.strip():
            last_error = "ExploitAgent returned empty test_code"
            attempts.append(
                ExploitAttempt(
                    attempt=attempt_no,
                    test_code="",
                    passed=False,
                    revert_reason=last_error,
                )
            )
            logger.info(
                "PoC attempt %s/%s for %s: compile_error=False reason=%s",
                attempt_no,
                max_attempts,
                candidate.id,
                last_error,
            )
            continue
        try:
            run = forge_tool.run_test(
                test_code,
                fork_block=fork_block,
                attempt=attempt_no,
                parent_dir=workdir / "forge",
                fork_url=fork_url,
            )
        except AuditorError as exc:
            logger.warning("Forge runner error on attempt %s: %s", attempt_no, exc)
            attempts.append(
                ExploitAttempt(
                    attempt=attempt_no,
                    test_code=test_code,
                    passed=False,
                    revert_reason=str(exc),
                    compile_error=True,
                )
            )
            last_error = str(exc)
            logger.info(
                "PoC attempt %s/%s for %s: compile_error=True reason=%s",
                attempt_no,
                max_attempts,
                candidate.id,
                str(exc)[:400],
            )
            continue

        attempt = forge_tool.to_attempt(test_code, run, attempt_no)
        attempts.append(attempt)
        if run.passed:
            logger.info("PoC CONFIRMED for %s on attempt %s", candidate.id, attempt_no)
            return Finding(
                candidate=candidate,
                status=FindingStatus.CONFIRMED,
                attempts=attempts,
                poc_code=test_code,
                remediation=remediation,
            )
        last_error = run.revert_reason or run.stderr or run.stdout or "forge test failed"
        logger.info(
            "PoC attempt %s/%s for %s: compile_error=%s reason=%s",
            attempt_no,
            max_attempts,
            candidate.id,
            run.compile_error,
            last_error[:400],
        )

    return Finding(
        candidate=candidate,
        status=FindingStatus.UNCONFIRMED,
        attempts=attempts,
        poc_code=previous_code or None,
        remediation=remediation,
    )


def strip_code_fences(code: str) -> str:
    """Remove markdown fences the model sometimes wraps around Solidity."""
    text = (code or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # drop first fence and optional language tag
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _source_count(contract: FetchedContract) -> int:
    count = len(contract.source_files)
    if contract.implementation:
        count += len(contract.implementation.source_files)
    return count


def stage_label(stage: str) -> str:
    """Human label for a pipeline stage id."""
    return STAGE_LABELS.get(stage, stage)
