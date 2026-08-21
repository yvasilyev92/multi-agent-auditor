"""Central configuration for models, retries, timeouts, and secrets.

All tunables live here so the rest of the codebase does not scatter env lookups.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

from auditor.errors import AuditorError

# Load `.env` from the repo root even if the process cwd is elsewhere.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# EIP-1967 implementation slot:
# keccak256("eip1967.proxy.implementation") - 1
EIP1967_IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)

ETHERSCAN_BASE_URL = "https://api.etherscan.io/v2/api"
CHAIN_ID = 1

# Pipeline stages, in display order.
STAGES = (
    "fetching",
    "static_analysis",
    "triage",
    "exploit_confirmation",
    "report",
)

STAGE_LABELS = {
    "fetching": "Fetching",
    "static_analysis": "Static analysis",
    "triage": "Triage",
    "exploit_confirmation": "Exploit confirmation",
    "report": "Report",
}


def _optional_int(name: str) -> int | None:
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise AuditorError(f"Environment variable {name} must be an integer, got {raw!r}") from exc


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise AuditorError(f"Environment variable {name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class Settings:
    """Runtime settings loaded from the environment."""

    openai_api_key: str
    openai_model: str
    etherscan_api_key: str
    infura_url: str
    max_retries: int
    default_fork_block: int | None
    etherscan_timeout_s: float
    slither_timeout_s: float
    forge_timeout_s: float
    solc_select_timeout_s: float
    rpc_timeout_s: float
    llm_source_char_limit: int
    log_level: str

    def require_secrets(self, *, etherscan: bool = True) -> None:
        """Raise if required keys are missing (checked at audit start).

        ``etherscan`` is False when source is injected from disk (fixture eval).
        """
        missing: list[str] = []
        if not self.openai_api_key:
            missing.append("OPENAI_API_KEY")
        if etherscan and not self.etherscan_api_key:
            missing.append("ETHERSCAN_API_KEY")
        if not self.infura_url or "<key>" in self.infura_url:
            missing.append("INFURA_URL")
        if missing:
            raise AuditorError(
                "Missing required secrets: "
                + ", ".join(missing)
                + ". Copy .env.example to .env and fill in the keys."
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load settings from the environment. Cached for the process lifetime."""
    return Settings(
        openai_api_key=os.getenv("OPENAI_API_KEY", "").strip(),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o").strip() or "gpt-4o",
        etherscan_api_key=os.getenv("ETHERSCAN_API_KEY", "").strip(),
        infura_url=os.getenv("INFURA_URL", "").strip(),
        max_retries=_int_env("MAX_RETRIES", 3),
        default_fork_block=_optional_int("DEFAULT_FORK_BLOCK"),
        etherscan_timeout_s=float(os.getenv("ETHERSCAN_TIMEOUT_S", "30")),
        slither_timeout_s=float(os.getenv("SLITHER_TIMEOUT_S", "180")),
        forge_timeout_s=float(os.getenv("FORGE_TIMEOUT_S", "300")),
        solc_select_timeout_s=float(os.getenv("SOLC_SELECT_TIMEOUT_S", "120")),
        rpc_timeout_s=float(os.getenv("RPC_TIMEOUT_S", "30")),
        llm_source_char_limit=_int_env("LLM_SOURCE_CHAR_LIMIT", 80_000),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    )
