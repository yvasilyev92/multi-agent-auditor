"""ForgeRunnerTool: throwaway Foundry project + fork test execution."""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from auditor.config import get_settings
from auditor.errors import ToolCommandError
from auditor.models import ExploitAttempt
from auditor.subprocess_utils import run_command, which
from auditor.util import extract_json_objects, is_local_rpc

logger = logging.getLogger(__name__)

_FAIL_STATUSES = {"failure", "failed", "revert", "error"}
_PASS_STATUSES = {"success", "passed", "ok"}

_FOUNDRY_TOML = """\
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "0.8.24"
optimizer = true
ffi = false
"""


class ForgeRunResult:
    """Outcome of one `forge test` invocation."""

    def __init__(
        self,
        passed: bool,
        stdout: str,
        stderr: str,
        revert_reason: str | None,
        compile_error: bool,
        workdir: str,
    ) -> None:
        self.passed = passed
        self.stdout = stdout
        self.stderr = stderr
        self.revert_reason = revert_reason
        self.compile_error = compile_error
        self.workdir = workdir


class ForgeRunnerTool:
    """Scaffold a throwaway Foundry project and run a generated exploit test on a fork."""

    def __init__(self) -> None:
        self._settings = get_settings()

    def run_test(
        self,
        test_code: str,
        *,
        fork_block: int | None,
        attempt: int,
        parent_dir: str | Path | None = None,
        fork_url: str | None = None,
    ) -> ForgeRunResult:
        """Write ``test_code`` into a fresh `forge init` project and run it."""
        forge = which(
            "forge",
            hint="Install Foundry: `curl -L https://foundry.paradigm.xyz | bash` then `foundryup`.",
        )
        root_parent = Path(parent_dir) if parent_dir else Path(tempfile.gettempdir())
        root_parent.mkdir(parents=True, exist_ok=True)
        rpc = fork_url or self._settings.infura_url
        local = is_local_rpc(rpc)

        with tempfile.TemporaryDirectory(prefix="forge-poc-", dir=str(root_parent)) as tmp:
            # Init into a child path so forge creates the project itself.
            project = Path(tmp) / "foundry"
            init = run_command(
                [forge, "init", "--force", "--no-git", str(project)],
                timeout=120,
            )
            if init.returncode != 0:
                logger.warning("forge init --no-git failed; retrying without --no-git")
                init = run_command(
                    [forge, "init", "--force", str(project)],
                    timeout=120,
                )
            if init.returncode != 0:
                raise ToolCommandError(
                    "forge init failed. Is Foundry installed and working?\n" + init.output[-3000:]
                )

            forge_std = project / "lib" / "forge-std"
            if not forge_std.exists():
                logger.warning("forge-std missing after init; attempting forge install")
                run_command(
                    [forge, "install", "foundry-rs/forge-std", "--no-git", "--shallow"],
                    timeout=120,
                    cwd=project,
                )

            test_dir = project / "test"
            test_dir.mkdir(exist_ok=True)
            # Avoid running the sample Counter test.
            counter_test = test_dir / "Counter.t.sol"
            if counter_test.exists():
                counter_test.unlink()
            (test_dir / "Exploit.t.sol").write_text(test_code, encoding="utf-8")
            (project / "foundry.toml").write_text(_FOUNDRY_TOML, encoding="utf-8")

            env = os.environ.copy()
            # Point vm.envString("INFURA_URL") at the same RPC forge --fork-url uses.
            env["INFURA_URL"] = rpc

            args = [
                forge,
                "test",
                "--fork-url",
                rpc,
                "--json",
                "-vvvv",
                "--match-path",
                "test/Exploit.t.sol",
            ]
            # A historical Infura block would drop Anvil-only deploys.
            if fork_block is not None and not local:
                args.extend(["--fork-block-number", str(fork_block)])

            logger.info(
                "Running forge test (attempt %s, rpc=%s, fork_block=%s, local=%s)",
                attempt,
                rpc,
                fork_block if not local else None,
                local,
            )
            result = run_command(
                args,
                timeout=self._settings.forge_timeout_s,
                cwd=project,
                env=env,
            )
            parsed = parse_forge_json(result.stdout) or parse_forge_json(result.output)
            compile_error = result.returncode != 0 and _looks_like_compile_error(result.output)
            if parsed is None:
                passed = result.returncode == 0
                reason = _tail(result.output, 4000) if not passed else None
            else:
                passed, reason = parsed
                if result.returncode != 0:
                    passed = False
                    reason = reason or _tail(result.output, 4000)

            logger.info(
                "forge test attempt %s: passed=%s compile_error=%s",
                attempt,
                passed,
                compile_error,
            )
            if not passed:
                kind = "compile error" if compile_error else "revert/fail"
                logger.info(
                    "forge test attempt %s %s:\n%s",
                    attempt,
                    kind,
                    _tail(reason or result.output, 2500),
                )
            return ForgeRunResult(
                passed=passed,
                stdout=result.stdout,
                stderr=result.stderr,
                revert_reason=reason,
                compile_error=compile_error,
                workdir=str(project),
            )

    def to_attempt(self, test_code: str, run: ForgeRunResult, attempt: int) -> ExploitAttempt:
        return ExploitAttempt(
            attempt=attempt,
            test_code=test_code,
            passed=run.passed,
            stdout=run.stdout[-8000:],
            stderr=run.stderr[-8000:],
            revert_reason=(run.revert_reason or "")[-4000:] or None,
            compile_error=run.compile_error,
        )


def parse_forge_json(text: str) -> tuple[bool, str | None] | None:
    """Walk Forge JSON (shape varies) looking for per-test status.

    Returns (all_passed, failure_reason) or None if no JSON could be parsed.
    """
    objects = extract_json_objects(text)
    if not objects:
        return None

    failures: list[str] = []
    successes: list[str] = []
    for obj in objects:
        _walk_forge_obj(obj, failures, successes)

    if failures:
        return False, "; ".join(failures[:8])
    if successes:
        return True, None
    # JSON present but no test statuses — likely a compiler/suite wrapper.
    return None


def _walk_forge_obj(obj: Any, failures: list[str], successes: list[str]) -> None:
    if isinstance(obj, dict):
        status = obj.get("status")
        if isinstance(status, str):
            lowered = status.lower()
            reason = _reason_from(obj)
            if lowered in _FAIL_STATUSES:
                failures.append(reason or status)
            elif lowered in _PASS_STATUSES:
                successes.append(status)

        failed_count = obj.get("failed")
        passed_count = obj.get("passed")
        if isinstance(failed_count, int) and failed_count > 0:
            failures.append(_reason_from(obj) or f"{failed_count} test(s) failed")
        if isinstance(passed_count, int) and passed_count > 0:
            successes.append("passed")

        for value in obj.values():
            _walk_forge_obj(value, failures, successes)
    elif isinstance(obj, list):
        for item in obj:
            _walk_forge_obj(item, failures, successes)


def _reason_from(obj: dict[str, Any]) -> str | None:
    for key in ("reason", "decoded_reason", "message", "error", "kind"):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, dict):
            nested = _reason_from(value)
            if nested:
                return nested
    return None


def _looks_like_compile_error(text: str) -> bool:
    lowered = text.lower()
    needles = (
        "compiler run failed",
        "compilation failed",
        "error (fail",
        "error[",
        "could not compile",
    )
    return any(n in lowered for n in needles) and "passed" not in lowered.split("fail", 1)[0][-80:]


def _tail(text: str, n: int) -> str:
    text = text.strip()
    return text[-n:] if len(text) > n else text
