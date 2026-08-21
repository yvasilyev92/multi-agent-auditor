"""Parser and helper tests that do not touch a network or an LLM."""

from __future__ import annotations

import pytest

from auditor.agents.exploit import _block_text
from auditor.agents.report import render_template_report
from auditor.errors import InvalidAddressError
from auditor.fixture_eval import write_poc_attempts
from auditor.models import (
    AuditResult,
    Candidate,
    ExploitAttempt,
    FetchedContract,
    Finding,
    FindingStatus,
    Severity,
)
from auditor.orchestrator import strip_code_fences
from auditor.tools.fetcher import FetcherTool, parse_source_code
from auditor.tools.forge_runner import parse_forge_json
from auditor.tools.static_analysis import parse_slither_json, pick_solc_version, version_from_pragma
from auditor.util import (
    checksum_address,
    checksum_solidity_addresses,
    extract_json_objects,
    is_local_rpc,
    storage_slot_to_address,
    validate_address,
)


def test_validate_address_normalizes() -> None:
    addr = validate_address("0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5")
    assert addr == "0xc1e088fc1323b20bcbee9bd1b9fc9546db5624c5"


def test_validate_address_rejects_garbage() -> None:
    with pytest.raises(InvalidAddressError):
        validate_address("not-an-address")


def test_checksum_address_eip55() -> None:
    lower = "0x2660047ce615159b301b87e7ad7004a783a6c28d"
    mixed = "0x2660047CE615159B301b87E7Ad7004a783A6c28D"
    assert checksum_address(lower) == mixed
    assert checksum_address(mixed) == mixed
    with pytest.raises(InvalidAddressError):
        checksum_address("not-an-address")


def test_checksum_solidity_addresses_rewrites_literals() -> None:
    src = (
        "address constant usdc = 0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48;\n"
        "address constant weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;\n"
    )
    out = checksum_solidity_addresses(src)
    assert "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" in out
    assert "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" in out


def test_storage_slot_to_address() -> None:
    impl = "c1e088fc1323b20bcbee9bd1b9fc9546db5624c5"
    word = "0x" + ("00" * 12) + impl
    assert storage_slot_to_address(word) == "0x" + impl
    assert storage_slot_to_address("0x" + "00" * 32) is None
    assert storage_slot_to_address("") is None


def test_parse_source_flat_solidity() -> None:
    files, remaps = parse_source_code(
        "pragma solidity ^0.8.0;\ncontract Foo {}",
        default_filename="Foo.sol",
    )
    assert list(files) == ["Foo.sol"]
    assert "contract Foo" in files["Foo.sol"]
    assert remaps == []


def test_parse_source_standard_json_double_wrapped() -> None:
    raw = (
        '{{"language":"Solidity","sources":{"a/A.sol":{"content":"pragma solidity ^0.8.0;"}},'
        '"settings":{"remappings":["@oz/=lib/oz/"]}}}'
    )
    files, remaps = parse_source_code(raw, default_filename="X.sol")
    assert files["a/A.sol"].startswith("pragma")
    assert remaps == ["@oz/=lib/oz/"]


def test_parse_source_old_multifile() -> None:
    files, remaps = parse_source_code(
        '{"Foo.sol":{"content":"hello"}}',
        default_filename="X.sol",
    )
    assert files["Foo.sol"] == "hello"
    assert remaps == []


def test_version_from_pragma() -> None:
    assert version_from_pragma("^0.8.20") == "0.8.20"
    assert version_from_pragma(">=0.7.6 <0.8.0") == "0.7.6"
    assert version_from_pragma("0.8.19") == "0.8.19"


def test_pick_solc_version_prefers_etherscan() -> None:
    contract = FetchedContract(
        address="0x" + "ab" * 20,
        name="X",
        compiler_version="v0.8.19+commit.7dd6d404",
        source_files=[],
    )
    assert pick_solc_version(contract) == "0.8.19"


def test_parse_slither_json() -> None:
    payload = (
        '{"success":true,"results":{"detectors":[{'
        '"check":"reentrancy-eth","impact":"High","confidence":"Medium",'
        '"description":"x","elements":[{"source_mapping":{"lines":[10,11],'
        '"filename_relative":"A.sol"}}]}]}}'
    )
    findings = parse_slither_json(payload)
    assert findings[0].check == "reentrancy-eth"
    assert findings[0].lines == [10, 11]
    assert findings[0].filenames == ["A.sol"]


def test_parse_forge_json_success_and_failure() -> None:
    ok = parse_forge_json(
        '{"results":{"test/Exploit.t.sol":{"ExploitTest":{"testExploit":{"status":"Success"}}}}}'
    )
    assert ok == (True, None)
    bad = parse_forge_json('{"status":"Failure","reason":"assertion failed"}')
    assert bad is not None
    passed, reason = bad
    assert passed is False
    assert reason is not None and "assertion" in reason


def test_strip_code_fences() -> None:
    assert strip_code_fences("```solidity\ncontract X {}\n```") == "contract X {}"
    assert strip_code_fences("contract X {}") == "contract X {}"


def test_is_local_rpc() -> None:
    assert is_local_rpc("http://127.0.0.1:8545")
    assert is_local_rpc("http://localhost:8545")
    assert not is_local_rpc("https://mainnet.infura.io/v3/abc")
    assert not is_local_rpc(None)


def test_load_local_from_file(tmp_path) -> None:
    src = tmp_path / "Vault.sol"
    src.write_text("pragma solidity ^0.8.24;\ncontract Vault { function x() external {} }\n")
    dest = tmp_path / "out"
    contract = FetcherTool().load_local("0x" + "ab" * 20, src, dest)
    assert contract.name == "Vault"
    assert contract.address.startswith("0xab")
    assert any("contract Vault" in f.content for f in contract.source_files)
    assert "local fixture" in contract.proxy_hint.lower()


def test_select_fixture_cases() -> None:
    from auditor.errors import AuditorError
    from auditor.fixture_eval import select_fixture_cases

    all_cases = select_fixture_cases(None)
    assert [c.name for c in all_cases] == [
        "ReentrancyVault",
        "OpenDrainWallet",
        "SpotOracleLender",
    ]
    assert select_fixture_cases(["all"])[0].name == "ReentrancyVault"
    assert len(select_fixture_cases(["all"])) == 3
    one = select_fixture_cases(["reentrancy"])
    assert [c.name for c in one] == ["ReentrancyVault"]
    two = select_fixture_cases(["drain", "oracle"])
    assert [c.name for c in two] == ["OpenDrainWallet", "SpotOracleLender"]
    with pytest.raises(AuditorError, match="Unknown fixture"):
        select_fixture_cases(["not-a-contract"])


def test_write_llm_report(tmp_path) -> None:
    from auditor.fixture_eval import write_llm_report

    dest = write_llm_report(tmp_path, "Reentrancy Vault", "# Hello\n\nbody", address="0xabc")
    assert dest.name == "Reentrancy-Vault.md"
    text = dest.read_text(encoding="utf-8")
    assert "Hello" in text
    assert "0xabc" in text


def test_parse_deploy_addresses() -> None:
    from auditor.fixture_eval import parse_deploy_addresses

    log = (
        "Deployer: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\n"
        "ReentrancyVault: 0x1111111111111111111111111111111111111111\n"
        "OpenDrainWallet: 0x2222222222222222222222222222222222222222\n"
        "SpotOracleLender: 0x3333333333333333333333333333333333333333\n"
    )
    found = parse_deploy_addresses(log)
    assert found["ReentrancyVault"].lower().endswith("1111")
    assert found["OpenDrainWallet"].lower().endswith("2222")
    assert found["SpotOracleLender"].lower().endswith("3333")


def test_render_template_report_includes_status() -> None:
    finding = Finding(
        candidate=Candidate(
            id="01-reentrancy",
            title="Reentrancy in withdraw",
            severity=Severity.HIGH,
            rationale="External call before state update.",
            category="reentrancy",
        ),
        status=FindingStatus.CONFIRMED,
        poc_code="contract ExploitTest {}",
        remediation="Use checks-effects-interactions.",
    )
    markdown = render_template_report(
        AuditResult(
            address="0x" + "11" * 20,
            contract_name="Vault",
            findings=[finding],
        )
    )
    assert "Reentrancy in withdraw" in markdown
    assert "CONFIRMED via PoC" in markdown
    assert "contract ExploitTest" in markdown
    assert "Disclaimer" in markdown


def test_exploit_prompt_asserts_balance_delta() -> None:
    from auditor.agents.exploit import _SYSTEM

    assert "2**96" in _SYSTEM
    assert "address(this).balance == stolenAmount" in _SYSTEM
    assert "BEFORE the call" in _SYSTEM
    assert "receive() external payable" in _SYSTEM
    assert "deal(WETH, account, amount)" in _SYSTEM
    assert "never WETH" in _SYSTEM
    assert "pre-manipulation max" in _SYSTEM
    assert "INSUFFICIENT_INPUT_AMOUNT" in _SYSTEM
    assert "reserveOut - 1" in _SYSTEM


def test_block_text_forbids_create_select_fork() -> None:
    local = _block_text(None, local_fork=True)
    latest = _block_text(None, local_fork=False)
    pinned = _block_text(14_602_789, local_fork=False)
    for text in (local, latest, pinned):
        assert "Do NOT call createSelectFork" in text
        assert "vm.createSelectFork" not in text


def test_write_poc_attempts_writes_sol_and_txt(tmp_path) -> None:
    finding = Finding(
        candidate=Candidate(
            id="01-reentrancy-vulnerability-in-withdraw-function",
            title="Reentrancy",
            severity=Severity.CRITICAL,
            rationale="call before zero",
            category="reentrancy",
        ),
        status=FindingStatus.UNCONFIRMED,
        attempts=[
            ExploitAttempt(
                attempt=2,
                test_code="contract ExploitTest {}",
                passed=False,
                revert_reason="assertion failed: attacker did not profit",
                compile_error=False,
            )
        ],
    )
    written = write_poc_attempts(tmp_path, "ReentrancyVault", [finding])
    sol = tmp_path / (
        "ReentrancyVault-01-reentrancy-vulnerability-in-withdraw-function-attempt-2.sol"
    )
    txt = tmp_path / (
        "ReentrancyVault-01-reentrancy-vulnerability-in-withdraw-function-attempt-2.txt"
    )
    assert sol in written and txt in written
    assert sol.read_text(encoding="utf-8") == "contract ExploitTest {}"
    body = txt.read_text(encoding="utf-8")
    assert "passed=False" in body
    assert "attacker did not profit" in body
