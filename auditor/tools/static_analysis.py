"""StaticAnalysisTool: pick solc via solc-select and run Slither JSON output."""

from __future__ import annotations

import logging
import re
from typing import Any

from auditor.config import get_settings
from auditor.errors import ToolCommandError, ToolNotFoundError, ToolTimeoutError
from auditor.models import FetchedContract, SlitherFinding, SourceFile
from auditor.subprocess_utils import run_command, which
from auditor.util import extract_json_objects

logger = logging.getLogger(__name__)

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_VERSION_RE = re.compile(r"\b(\d+\.\d+\.\d+)\b")
_CARET_RE = re.compile(r"\^(\d+\.\d+\.\d+)")
_GE_RE = re.compile(r">=\s*(\d+\.\d+\.\d+)")
_ETHERSCAN_SOLC_RE = re.compile(r"v?(\d+\.\d+\.\d+)")


class StaticAnalysisResult:
    """Parsed Slither findings plus optional degraded-mode error."""

    def __init__(self, findings: list[SlitherFinding], error: str | None = None, solc_version: str = "") -> None:
        self.findings = findings
        self.error = error
        self.solc_version = solc_version


class StaticAnalysisTool:
    """Run Slither against reconstructed sources. Never abort the whole audit."""

    def __init__(self) -> None:
        self._settings = get_settings()

    def analyze(self, contract: FetchedContract) -> StaticAnalysisResult:
        """Analyze the implementation if present, otherwise the fetched contract."""
        target = contract.implementation or contract
        solc_version = pick_solc_version(target)
        logger.info("Using solc %s for %s", solc_version, target.name)

        try:
            self._ensure_solc(solc_version)
        except (ToolNotFoundError, ToolCommandError, ToolTimeoutError) as exc:
            logger.warning("solc-select failed; continuing without Slither: %s", exc)
            return StaticAnalysisResult([], error=str(exc), solc_version=solc_version)

        try:
            slither_bin = which(
                "slither",
                hint="Install Python deps with `uv sync` so slither is on the uv-managed PATH.",
            )
            args = [
                slither_bin,
                target.workdir,
                "--json",
                "-",
                "--solc-solcs-select",
                solc_version,
            ]
            remaps = _slither_remap_args(target.remappings)
            if remaps:
                args.extend(remaps)

            result = run_command(args, timeout=self._settings.slither_timeout_s, cwd=target.workdir)
            if result.returncode != 0 and _unknown_argument(result.output):
                logger.warning("Slither rejected --solc-solcs-select; retrying without it")
                args = [slither_bin, target.workdir, "--json", "-"]
                if remaps:
                    args.extend(remaps)
                result = run_command(args, timeout=self._settings.slither_timeout_s, cwd=target.workdir)
            findings = parse_slither_json(result.stdout) or parse_slither_json(result.output)
            if result.returncode != 0 and not findings:
                # Slither uses non-zero exit when it finds issues; that's not a failure.
                # Only treat it as degraded if we also failed to parse JSON.
                if not extract_json_objects(result.output):
                    message = result.output[-4000:] or f"slither exit {result.returncode}"
                    logger.warning("Slither produced no parseable JSON: %s", message[:500])
                    return StaticAnalysisResult([], error=message, solc_version=solc_version)
            logger.info("Slither returned %s detector finding(s)", len(findings))
            return StaticAnalysisResult(findings, solc_version=solc_version)
        except (ToolNotFoundError, ToolCommandError, ToolTimeoutError) as exc:
            logger.warning("Slither failed; triage will use source only: %s", exc)
            return StaticAnalysisResult([], error=str(exc), solc_version=solc_version)
        except Exception as exc:  # noqa: BLE001 — never abort the audit on Slither
            logger.exception("Unexpected Slither failure")
            return StaticAnalysisResult([], error=str(exc), solc_version=solc_version)

    def _ensure_solc(self, version: str) -> None:
        solc_select = which(
            "solc-select",
            hint="Install with `uv tool install solc-select` (see README).",
        )
        installed = run_command(
            [solc_select, "versions"],
            timeout=self._settings.solc_select_timeout_s,
        )
        already = version in (installed.stdout + installed.stderr)
        if already:
            logger.info("solc %s already installed via solc-select", version)
            return
        logger.info("Installing solc %s via solc-select", version)
        run_command(
            [solc_select, "install", version],
            timeout=self._settings.solc_select_timeout_s,
            check=True,
        )


def pick_solc_version(contract: FetchedContract) -> str:
    """Prefer Etherscan's compiler version; fall back to pragma parsing."""
    match = _ETHERSCAN_SOLC_RE.search(contract.compiler_version or "")
    if match:
        return match.group(1)
    pragma = _first_pragma(contract.source_files)
    if pragma:
        return version_from_pragma(pragma)
    logger.warning("No compiler version or pragma found; defaulting to 0.8.24")
    return "0.8.24"


def _first_pragma(files: list[SourceFile]) -> str | None:
    for source in files:
        match = _PRAGMA_RE.search(source.content)
        if match:
            return match.group(1).strip()
    return None


def version_from_pragma(pragma_expr: str) -> str:
    """Pick a concrete solc-select version from a pragma expression."""
    caret = _CARET_RE.search(pragma_expr)
    if caret:
        return caret.group(1)
    ge = _GE_RE.search(pragma_expr)
    if ge:
        return ge.group(1)
    exact = _VERSION_RE.search(pragma_expr)
    if exact:
        return exact.group(1)
    return "0.8.24"


def _slither_remap_args(remappings: list[str]) -> list[str]:
    if not remappings:
        return []
    joined = " ".join(remappings)
    return ["--solc-remaps", joined]


def _unknown_argument(output: str) -> bool:
    lowered = output.lower()
    return "unrecognized arguments" in lowered or "invalid argument" in lowered or "no such option" in lowered


def parse_slither_json(text: str) -> list[SlitherFinding]:
    """Defensively parse Slither `--json` output (shape has changed across versions)."""
    findings: list[SlitherFinding] = []
    for obj in extract_json_objects(text):
        findings.extend(_findings_from_object(obj))
    return findings


def _findings_from_object(obj: Any) -> list[SlitherFinding]:
    detectors: list[Any] = []
    if isinstance(obj, dict):
        results = obj.get("results")
        if isinstance(results, dict) and isinstance(results.get("detectors"), list):
            detectors = results["detectors"]
        elif isinstance(obj.get("detectors"), list):
            detectors = obj["detectors"]
        elif isinstance(obj.get("results"), list):
            detectors = obj["results"]
    elif isinstance(obj, list):
        detectors = obj

    parsed: list[SlitherFinding] = []
    for item in detectors:
        if not isinstance(item, dict):
            continue
        check = str(item.get("check") or item.get("id") or item.get("name") or "unknown")
        impact = str(item.get("impact") or item.get("severity") or "Unknown")
        confidence = str(item.get("confidence") or "Unknown")
        description = str(item.get("description") or item.get("markdown") or "")
        elements = item.get("elements") if isinstance(item.get("elements"), list) else []
        lines, filenames = _lines_and_files(elements)
        parsed.append(
            SlitherFinding(
                check=check,
                impact=impact,
                confidence=confidence,
                description=description.strip(),
                elements=[e for e in elements if isinstance(e, dict)],
                lines=lines,
                filenames=filenames,
            )
        )
    return parsed


def _lines_and_files(elements: list[Any]) -> tuple[list[int], list[str]]:
    lines: list[int] = []
    filenames: list[str] = []
    for element in elements:
        if not isinstance(element, dict):
            continue
        mapping = element.get("source_mapping") if isinstance(element.get("source_mapping"), dict) else {}
        raw_lines = mapping.get("lines") or element.get("lines") or []
        if isinstance(raw_lines, list):
            for line in raw_lines:
                try:
                    lines.append(int(line))
                except (TypeError, ValueError):
                    continue
        for key in ("filename_relative", "filename_used", "filename", "name"):
            value = mapping.get(key) or element.get(key)
            if value:
                filenames.append(str(value))
                break
    # Preserve order, drop dupes.
    uniq_lines = list(dict.fromkeys(lines))
    uniq_files = list(dict.fromkeys(filenames))
    return uniq_lines, uniq_files
