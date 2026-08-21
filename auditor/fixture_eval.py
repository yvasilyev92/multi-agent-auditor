"""Deploy fixture contracts onto Anvil and score the auditor against them."""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from auditor.anvil import ANVIL_PRIVATE_KEY, AnvilInstance, start_anvil
from auditor.config import get_settings
from auditor.errors import AuditorError, ToolCommandError
from auditor.models import FindingStatus, Severity
from auditor.orchestrator import run_audit
from auditor.subprocess_utils import run_command, which

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "fixtures"
REPORTS_DIR = REPO_ROOT / "test-pipeline-llm-reports"

USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
USDC_WHALES = (
    "0x55FE002aefF02F77364de339a1292923A15844B8",  # Circle
    "0x28C6c06298d514Db089934071355E5743bf21d60",  # Binance 14
    "0x47ac0Fb4F2D84898e4D9E7b4DaB3C24507a6D503",  # Binance 8
)
USDC_FUND_AMOUNT = 1_000_000 * 10**6  # 1,000,000 USDC


@dataclass(frozen=True)
class FixtureCase:
    """One intentionally vulnerable contract deployed by the fixture script."""

    name: str
    source_file: str
    expected_categories: tuple[str, ...]
    notes: str
    match_test: str
    aliases: tuple[str, ...] = ()


FIXTURE_CASES: tuple[FixtureCase, ...] = (
    FixtureCase(
        name="ReentrancyVault",
        source_file="ReentrancyVault.sol",
        expected_categories=("reentrancy",),
        notes="withdraw() sends ETH before zeroing balances.",
        match_test="testReentrancyDrainsVault",
        aliases=("reentrancy", "vault"),
    ),
    FixtureCase(
        name="OpenDrainWallet",
        source_file="OpenDrainWallet.sol",
        expected_categories=("access_control",),
        notes="withdrawAll() has no onlyOwner check.",
        match_test="testOpenDrainAnyoneCanWithdraw",
        aliases=("opendrain", "drain", "wallet"),
    ),
    FixtureCase(
        name="SpotOracleLender",
        source_file="SpotOracleLender.sol",
        expected_categories=("oracle", "price"),
        notes="Collateral priced from Uniswap V2 getReserves().",
        match_test="testSpotOracleManipulation",
        aliases=("oracle", "spot", "lender"),
    ),
)


def available_fixture_names() -> str:
    """Human-readable list of selectable fixture contracts."""
    parts = []
    for case in FIXTURE_CASES:
        alias = ", ".join(case.aliases)
        parts.append(f"{case.name} (aliases: {alias})")
    return "; ".join(parts)


def select_fixture_cases(names: list[str] | None) -> list[FixtureCase]:
    """Resolve CLI names/aliases to fixture cases. ``None`` or ``['all']`` → every case."""
    if not names:
        return list(FIXTURE_CASES)
    cleaned = [n.strip() for n in names if n and n.strip()]
    if not cleaned or any(_normalize_fixture_key(n) in {"all", "*"} for n in cleaned):
        return list(FIXTURE_CASES)

    by_key: dict[str, FixtureCase] = {}
    for case in FIXTURE_CASES:
        by_key[_normalize_fixture_key(case.name)] = case
        for alias in case.aliases:
            by_key[_normalize_fixture_key(alias)] = case

    selected: list[FixtureCase] = []
    unknown: list[str] = []
    for raw in cleaned:
        case = by_key.get(_normalize_fixture_key(raw))
        if case is None:
            unknown.append(raw)
        elif case not in selected:
            selected.append(case)
    if unknown:
        raise AuditorError(
            "Unknown fixture contract(s): "
            + ", ".join(unknown)
            + f". Choose from: {available_fixture_names()}, or 'all'."
        )
    return selected


def _normalize_fixture_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def run_fixture_eval(*, contracts: list[str] | None = None) -> int:
    """Start Anvil, deploy fixtures, run reference PoCs, then the full auditor pipeline."""
    try:
        selected = select_fixture_cases(contracts)
    except AuditorError as exc:
        print(str(exc))
        return 2

    print("Fixture contracts: " + ", ".join(c.name for c in selected))

    settings = get_settings()
    settings.require_secrets(etherscan=False)

    anvil: AnvilInstance | None = None
    try:
        anvil = start_anvil(settings.infura_url)
        _ensure_forge_std()
        addresses = deploy_fixtures(anvil.url)
        print("Deployed on Anvil fork:")
        for name, addr in addresses.items():
            print(f"  {name}: {addr}")
        print()

        lender = addresses.get("SpotOracleLender")
        if lender and any(c.name == "SpotOracleLender" for c in selected):
            fund_lender_usdc(anvil.url, lender)

        _run_reference_tests(anvil.url, addresses, selected)
        print("Reference Foundry exploits passed.\n")

        return _audit_fixtures(selected, addresses, anvil.url)
    finally:
        if anvil is not None:
            anvil.close()


def deploy_fixtures(rpc_url: str) -> dict[str, str]:
    """Broadcast Deploy.s.sol to Anvil and return contractName -> address."""
    forge = which("forge", hint="Install Foundry (`foundryup`).")
    env = os.environ.copy()
    env["PRIVATE_KEY"] = ANVIL_PRIVATE_KEY
    logger.info("Deploying fixtures via forge script to %s", rpc_url)
    result = run_command(
        [
            forge,
            "script",
            "script/Deploy.s.sol:DeployScript",
            "--rpc-url",
            rpc_url,
            "--broadcast",
            "--private-key",
            ANVIL_PRIVATE_KEY,
            "-vvv",
        ],
        timeout=180,
        cwd=FIXTURES_DIR,
        env=env,
    )
    if result.returncode != 0:
        raise ToolCommandError("Fixture deploy failed:\n" + result.output[-4000:])
    addresses = parse_deploy_addresses(result.output)
    if len(addresses) < 3:
        addresses.update(_addresses_from_broadcast())
    missing = [c.name for c in FIXTURE_CASES if c.name not in addresses]
    if missing:
        raise AuditorError(
            f"Could not parse deployed addresses for {missing}. Output:\n{result.output[-3000:]}"
        )
    return addresses


def parse_deploy_addresses(output: str) -> dict[str, str]:
    """Parse `console2.log("Name:", addr)` lines from forge script output."""
    found: dict[str, str] = {}
    for name in (case.name for case in FIXTURE_CASES):
        match = re.search(rf"{re.escape(name)}:\s*(0x[0-9a-fA-F]{{40}})", output)
        if match:
            found[name] = match.group(1)
    return found


def _addresses_from_broadcast() -> dict[str, str]:
    broadcast = FIXTURES_DIR / "broadcast" / "Deploy.s.sol" / "1" / "run-latest.json"
    if not broadcast.exists():
        return {}
    try:
        data = json.loads(broadcast.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    found: dict[str, str] = {}
    for tx in data.get("transactions") or []:
        if not isinstance(tx, dict):
            continue
        name = tx.get("contractName")
        addr = tx.get("contractAddress") or tx.get("address")
        if name and addr:
            found[str(name)] = str(addr)
    return found


def fund_lender_usdc(rpc_url: str, lender: str) -> None:
    """Impersonate a mainnet USDC whale on Anvil and fund the lender."""
    cast = which("cast", hint="Install Foundry (`foundryup`).")
    amount = str(USDC_FUND_AMOUNT)
    last_error = "unknown"
    for whale in USDC_WHALES:
        logger.info("Trying to fund lender from whale %s", whale)
        run_command(
            [cast, "rpc", "anvil_impersonateAccount", whale, "--rpc-url", rpc_url],
            timeout=30,
        )
        run_command(
            [cast, "rpc", "anvil_setBalance", whale, "0x56BC75E2D63100000", "--rpc-url", rpc_url],
            timeout=30,
        )
        result = run_command(
            [
                cast,
                "send",
                USDC,
                "transfer(address,uint256)",
                lender,
                amount,
                "--from",
                whale,
                "--unlocked",
                "--rpc-url",
                rpc_url,
            ],
            timeout=60,
        )
        if result.returncode == 0:
            logger.info("Funded SpotOracleLender with USDC from %s", whale)
            return
        last_error = result.output[-1500:]
    raise AuditorError(f"Could not transfer USDC to the lender from known whales: {last_error}")


def _run_reference_tests(
    rpc_url: str,
    addresses: dict[str, str],
    selected: list[FixtureCase],
) -> None:
    forge = which("forge", hint="Install Foundry (`foundryup`).")
    env = os.environ.copy()
    env["VAULT"] = addresses["ReentrancyVault"]
    env["WALLET"] = addresses["OpenDrainWallet"]
    env["LENDER"] = addresses["SpotOracleLender"]
    env["INFURA_URL"] = rpc_url
    match_test = "|".join(case.match_test for case in selected)
    result = run_command(
        [
            forge,
            "test",
            "--fork-url",
            rpc_url,
            "--match-path",
            "test/ReferenceExploits.t.sol",
            "--match-test",
            match_test,
            "-vv",
        ],
        timeout=180,
        cwd=FIXTURES_DIR,
        env=env,
    )
    if result.returncode != 0:
        raise ToolCommandError(
            "Reference fixture exploits failed — the fixtures themselves are not exploitable "
            "on this fork.\n" + result.output[-4000:]
        )


def _audit_fixtures(
    selected: list[FixtureCase],
    addresses: dict[str, str],
    rpc_url: str,
) -> int:
    print("AI Multi-Agent Auditor — fixture scorecard")
    print("PoCs run against the local Anvil mainnet fork (nothing broadcast to Ethereum).\n")

    run_dir = create_report_run_dir()
    print(f"LLM reports → {run_dir}\n")

    hits = misses = pocs = confirmed = 0
    rows: list[str] = []
    for case in selected:
        address = addresses[case.name]
        source = FIXTURES_DIR / "src" / case.source_file
        print(f"=== {case.name} ({address})")
        print(f"    {case.notes}")
        try:
            result = run_audit(
                address,
                fork_url=rpc_url,
                local_source_dir=source,
            )
        except AuditorError as exc:
            print(f"    ERROR: {exc}\n")
            rows.append(f"{case.name:<22} ERROR")
            misses += 1
            continue
        except Exception as exc:  # noqa: BLE001
            logger.exception("Fixture audit crashed for %s", case.name)
            print(f"    ERROR: {exc}\n")
            rows.append(f"{case.name:<22} ERROR")
            misses += 1
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
        write_poc_attempts(run_dir, case.name, result.findings)

        if _is_hit(result.findings, case.expected_categories, require_confirmed=True):
            verdict = "HIT"
            hits += 1
        elif _is_hit(result.findings, case.expected_categories, require_confirmed=False):
            verdict = "HIT (unconfirmed)"
            hits += 1
        else:
            verdict = "MISS"
            misses += 1

        print(
            f"    findings={len(result.findings)} confirmed={len(case_confirmed)} "
            f"critical/high={len(high)} → {verdict}"
        )
        print(f"    report: {report_path}")
        for finding in result.findings:
            print(
                f"      - [{finding.candidate.severity.value} / {finding.status_label}] "
                f"{finding.candidate.title} ({finding.candidate.category})"
            )
        print()
        rows.append(
            f"{case.name:<22} {verdict:<18} findings={len(result.findings)} "
            f"confirmed={len(case_confirmed)}"
        )

    print("─" * 64)
    print("Scorecard")
    for row in rows:
        print("  " + row)
    print()
    print(f"  hits:                    {hits}")
    print(f"  misses:                  {misses}")
    print(f"  PoC attempts generated:  {pocs}")
    print(f"  PoCs that passed:        {confirmed}")
    print()
    print("Disclaimer: automated first-pass. Human review still required.")
    return 0 if misses == 0 else 1


def create_report_run_dir() -> Path:
    """Create a timestamped folder under ``test-pipeline-llm-reports/``."""
    stamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    path = REPORTS_DIR / stamp
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_llm_report(
    run_dir: Path,
    name: str,
    markdown: str,
    *,
    address: str = "",
) -> Path:
    """Write one audit's markdown report to ``run_dir/<name>.md``."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "report"
    dest = run_dir / f"{safe}.md"
    body = (markdown or "").strip()
    if not body:
        body = f"# {name}\n\n(empty LLM report)\n"
    if address and address not in body[:400]:
        body = f"<!-- address: {address} -->\n\n{body}"
    dest.write_text(body + "\n", encoding="utf-8")
    logger.info("Wrote LLM report %s", dest)
    return dest


def write_poc_attempts(run_dir: Path, name: str, findings) -> list[Path]:
    """Write each PoC attempt's Solidity and forge error next to the markdown report."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "report"
    written: list[Path] = []
    for finding in findings:
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", finding.candidate.id).strip("-") or "finding"
        for attempt in finding.attempts:
            stem = f"{safe}-{slug}-attempt-{attempt.attempt}"
            sol_path = run_dir / f"{stem}.sol"
            txt_path = run_dir / f"{stem}.txt"
            sol_path.write_text(attempt.test_code or "", encoding="utf-8")
            kind = "compile error" if attempt.compile_error else "revert/fail"
            if attempt.passed:
                kind = "passed"
            body = (
                f"attempt={attempt.attempt} passed={attempt.passed} "
                f"compile_error={attempt.compile_error} ({kind})\n\n"
                f"{attempt.revert_reason or '(no revert_reason)'}\n"
            )
            extra = (attempt.stderr or attempt.stdout or "").strip()
            if extra and extra not in body:
                body += "\n--- forge output ---\n" + extra[-8000:] + "\n"
            txt_path.write_text(body, encoding="utf-8")
            written.extend([sol_path, txt_path])
            logger.info("Wrote PoC attempt %s", sol_path)
    return written


def _is_hit(findings, expected: tuple[str, ...], *, require_confirmed: bool) -> bool:
    expected_l = tuple(c.lower() for c in expected)
    for finding in findings:
        if require_confirmed and finding.status is not FindingStatus.CONFIRMED:
            continue
        if not require_confirmed and finding.candidate.severity not in {
            Severity.CRITICAL,
            Severity.HIGH,
        }:
            continue
        blob = " ".join(
            [
                finding.candidate.category,
                finding.candidate.title,
                finding.candidate.rationale,
            ]
        ).lower()
        if any(token in blob for token in expected_l):
            return True
    return False


def _ensure_forge_std() -> None:
    forge_std = FIXTURES_DIR / "lib" / "forge-std"
    if forge_std.exists():
        return
    forge = which("forge", hint="Install Foundry (`foundryup`).")
    logger.info("Installing forge-std into fixtures/")
    result = run_command(
        [forge, "install", "foundry-rs/forge-std", "--no-git", "--shallow"],
        timeout=120,
        cwd=FIXTURES_DIR,
    )
    if result.returncode != 0:
        result = run_command(
            [forge, "install", "foundry-rs/forge-std", "--no-git"],
            timeout=120,
            cwd=FIXTURES_DIR,
        )
    if result.returncode != 0 or not forge_std.exists():
        raise ToolCommandError(
            "Could not install forge-std into fixtures/. "
            "From the repo root run: `cd fixtures && forge install foundry-rs/forge-std --no-commit`\n"
            + result.output[-2000:]
        )
