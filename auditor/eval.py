"""Eval CLI: fixture contracts on an Anvil fork, plus optional historical cases.

Run with:

    uv run python -m auditor.eval
    uv run python -m auditor.eval --fixtures
    uv run python -m auditor.eval --historical
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass

from auditor.errors import AuditorError
from auditor.fixture_eval import (
    available_fixture_names,
    create_report_run_dir,
    run_fixture_eval,
    write_llm_report,
)
from auditor.logging_setup import setup_logging
from auditor.models import FindingStatus, Severity
from auditor.orchestrator import run_audit

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EvalCase:
    """One contract to score against a historical fork block."""

    name: str
    address: str
    fork_block: int
    notes: str
    expect_vulnerable: bool
    expected_categories: tuple[str, ...] = ()


CASES: tuple[EvalCase, ...] = (
    EvalCase(
        name="Beanstalk Diamond",
        address="0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5",
        fork_block=14_602_789,
        notes="Governance/flash-loan exploit of April 2022. Fork is one block before the attack.",
        expect_vulnerable=True,
        expected_categories=("access_control", "governance", "flashloan", "invariant"),
    ),
    EvalCase(
        name="Euler eDAI",
        address="0xe025E3ca2bE02316033184551D4d3Aa22024D9DC",
        fork_block=16_817_995,
        notes="Donation/liquidation attack of March 2023. Fork is one block before the attack.",
        expect_vulnerable=True,
        expected_categories=("accounting", "liquidation", "donation", "invariant"),
    ),
    EvalCase(
        name="USDC proxy",
        address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        fork_block=19_000_000,
        notes="Widely used fiat token proxy. Used as a false-positive control (should not confirm theft).",
        expect_vulnerable=False,
        expected_categories=(),
    ),
)


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m auditor.eval``."""
    parser = argparse.ArgumentParser(
        description=(
            "Run the auditor against Anvil-deployed fixture contracts (default) "
            "or optional historical mainnet cases."
        )
    )
    parser.add_argument(
        "--fixtures",
        action="store_true",
        help="Deploy intentional vulns on a local Anvil mainnet fork and audit them (default).",
    )
    parser.add_argument(
        "--historical",
        action="store_true",
        help="Audit known mainnet contracts at a fork block just before a historical exploit.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run the auditor against all 3 fixture contracts (default).",
    )
    parser.add_argument(
        "-c",
        "--contract",
        action="append",
        dest="contracts",
        metavar="NAME",
        help=(
            "Fixture contract to audit. Repeat to pick several. "
            f"Choices: {available_fixture_names()}. "
            "Default is all 3."
        ),
    )
    parser.add_argument(
        "--only",
        help="Alias of --contract for fixtures, or substring filter for --historical (e.g. beanstalk).",
    )
    args = parser.parse_args(argv)

    setup_logging()
    run_fixtures = args.fixtures or not args.historical
    fixture_names: list[str] | None
    if args.all and not args.contracts:
        fixture_names = None
    elif args.contracts:
        fixture_names = args.contracts
    elif args.only and run_fixtures and not args.historical:
        fixture_names = [args.only]
    else:
        fixture_names = None

    code = 0
    if run_fixtures:
        code = run_fixture_eval(contracts=fixture_names)
    if args.historical:
        hist = _run_historical(only=args.only)
        code = code or hist
    return code


def _run_historical(*, only: str | None) -> int:
    selected = [
        case
        for case in CASES
        if only is None or only.lower() in case.name.lower()
    ]
    if not selected:
        print("No historical eval cases matched.", file=sys.stderr)
        return 2

    print("AI Multi-Agent Auditor — historical eval scorecard")
    print("PoCs run only on a local Foundry mainnet fork.\n")

    run_dir = create_report_run_dir()
    print(f"LLM reports → {run_dir}\n")

    rows: list[str] = []
    hits = misses = false_positives = clean = pocs = confirmed = 0

    for case in selected:
        print(f"=== {case.name} ({case.address}) @ block {case.fork_block}")
        print(f"    {case.notes}")
        try:
            result = run_audit(case.address, fork_block=case.fork_block)
        except AuditorError as exc:
            print(f"    ERROR: {exc}\n")
            rows.append(f"{case.name:<22} ERROR")
            misses += 1 if case.expect_vulnerable else 0
            continue
        except Exception as exc:  # noqa: BLE001
            logger.exception("Eval case %s crashed", case.name)
            print(f"    ERROR: {exc}\n")
            rows.append(f"{case.name:<22} ERROR")
            continue

        case_confirmed = [f for f in result.findings if f.status is FindingStatus.CONFIRMED]
        high = [
            f
            for f in result.findings
            if f.candidate.severity in {Severity.CRITICAL, Severity.HIGH}
        ]
        pocs += sum(len(f.attempts) for f in result.findings)
        confirmed += len(case_confirmed)
        report_path = write_llm_report(
            run_dir,
            case.name,
            result.report_markdown,
            address=result.address,
        )

        categories = {f.candidate.category.lower() for f in result.findings}
        matched_category = (
            bool(set(case.expected_categories) & categories) if case.expected_categories else bool(high)
        )

        if case.expect_vulnerable:
            if case_confirmed or matched_category:
                verdict = "HIT"
                hits += 1
            else:
                verdict = "MISS"
                misses += 1
        else:
            if case_confirmed:
                verdict = "FALSE POSITIVE"
                false_positives += 1
            else:
                verdict = "CLEAN"
                clean += 1

        print(
            f"    findings={len(result.findings)} confirmed={len(case_confirmed)} "
            f"critical/high={len(high)} proxy={result.is_proxy} → {verdict}"
        )
        print(f"    report: {report_path}")
        for finding in result.findings:
            print(
                f"      - [{finding.candidate.severity.value} / {finding.status_label}] "
                f"{finding.candidate.title}"
            )
        print()
        rows.append(
            f"{case.name:<22} {verdict:<16} findings={len(result.findings)} "
            f"confirmed={len(case_confirmed)}"
        )

    print("─" * 64)
    print("Scorecard")
    for row in rows:
        print("  " + row)
    print()
    print(f"  hits (known-vulnerable): {hits}")
    print(f"  misses:                  {misses}")
    print(f"  false positives:         {false_positives}")
    print(f"  clean controls:          {clean}")
    print(f"  PoC attempts generated:  {pocs}")
    print(f"  PoCs that passed:        {confirmed}")
    print()
    print("Disclaimer: automated first-pass. Human review still required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
