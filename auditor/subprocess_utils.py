"""Bounded subprocess helpers. Never hang; always capture stdout and stderr."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from auditor.errors import ToolCommandError, ToolNotFoundError, ToolTimeoutError

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Captured result of a CLI invocation."""

    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def output(self) -> str:
        """Combined stdout then stderr, useful for feeding back to an LLM."""
        parts = []
        if self.stdout.strip():
            parts.append(self.stdout)
        if self.stderr.strip():
            parts.append(self.stderr)
        return "\n".join(parts).strip()


def which(executable: str, hint: str) -> str:
    """Return the absolute path to ``executable`` or raise a helpful error."""
    path = shutil.which(executable)
    if not path:
        raise ToolNotFoundError(
            f"`{executable}` was not found on PATH. {hint}"
        )
    return path


def run_command(
    args: list[str],
    *,
    timeout: float,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = False,
) -> CommandResult:
    """Run a command with a hard timeout, capturing stdout and stderr as text.

    Parameters
    ----------
    args:
        Argument vector (not a shell string).
    timeout:
        Seconds before the process is killed.
    cwd:
        Optional working directory.
    env:
        Optional environment overlay (replaces the full env if provided).
    check:
        If True, raise ``ToolCommandError`` on a non-zero exit.
    """
    logger.debug("Running command: %s (cwd=%s, timeout=%ss)", " ".join(args), cwd, timeout)
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolNotFoundError(
            f"`{args[0]}` was not found on PATH. Is the CLI installed?"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        message = (
            f"Command timed out after {timeout}s: {' '.join(args)}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )
        logger.error(message)
        raise ToolTimeoutError(message) from exc

    result = CommandResult(
        args=list(args),
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
    logger.debug(
        "Command finished rc=%s stdout_len=%s stderr_len=%s",
        result.returncode,
        len(result.stdout),
        len(result.stderr),
    )
    if check and result.returncode != 0:
        raise ToolCommandError(
            f"Command failed (exit {result.returncode}): {' '.join(args)}\n"
            f"{result.output}"
        )
    return result
