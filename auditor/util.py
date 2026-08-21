"""Small helpers for addresses, JSON extraction, and source packaging."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from eth_utils import to_checksum_address

from auditor.errors import InvalidAddressError
from auditor.models import FetchedContract, SourceFile

logger = logging.getLogger(__name__)

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def is_local_rpc(url: str | None) -> bool:
    """True when ``url`` points at a local Anvil/Hardhat-style RPC."""
    if not url:
        return False
    lowered = url.lower()
    return any(
        token in lowered
        for token in ("127.0.0.1", "localhost", "0.0.0.0", "host.docker.internal")
    )


def validate_address(value: str) -> str:
    """Normalize and validate a 20-byte hex address."""
    addr = (value or "").strip()
    if not _ADDRESS_RE.fullmatch(addr):
        raise InvalidAddressError(
            f"Invalid Ethereum address {value!r}. Expected 0x followed by 40 hex characters."
        )
    return "0x" + addr[2:].lower()


def checksum_address(value: str) -> str:
    """EIP-55 checksum so Solidity address literals compile.

    Internals stay lowercase via ``validate_address``; this form is for generated
    Foundry tests that paste ``address constant TARGET = 0x…``.
    """
    return to_checksum_address(validate_address(value))


_SOLIDITY_ADDR_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")


def checksum_solidity_addresses(code: str) -> str:
    """Rewrite every 20-byte hex literal in Solidity to EIP-55 checksum form."""

    def _repl(match: re.Match[str]) -> str:
        try:
            return checksum_address(match.group(0))
        except InvalidAddressError:
            return match.group(0)

    return _SOLIDITY_ADDR_RE.sub(_repl, code or "")


def storage_slot_to_address(slot_value: str | None) -> str | None:
    """Extract a 20-byte address from a 32-byte storage word, or None if empty."""
    if not slot_value:
        return None
    raw = slot_value.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if len(raw) < 40:
        raw = raw.zfill(40)
    addr = "0x" + raw[-40:]
    if int(addr, 16) == 0:
        return None
    return addr


def extract_json_objects(text: str) -> list[Any]:
    """Best-effort extraction of JSON values from mixed CLI output."""
    if not text or not text.strip():
        return []
    stripped = text.strip()
    try:
        return [json.loads(stripped)]
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    objects: list[Any] = []
    idx = 0
    length = len(stripped)
    while idx < length:
        if stripped[idx] not in "{[":
            idx += 1
            continue
        try:
            obj, end = decoder.raw_decode(stripped, idx)
            objects.append(obj)
            idx = end
        except json.JSONDecodeError:
            idx += 1
    return objects


def format_sources_for_llm(
    files: list[SourceFile],
    *,
    max_chars: int,
    header: str | None = None,
) -> str:
    """Join source files with path banners, truncating to a character budget."""
    parts: list[str] = []
    if header:
        parts.append(header)
        used = len(header) + 2
    else:
        used = 0

    for source in files:
        banner = f"// ===== FILE: {source.path} =====\n"
        chunk = banner + source.content + "\n"
        remaining = max_chars - used
        if remaining <= 0:
            parts.append("// [remaining files omitted to fit the model context window]")
            break
        if len(chunk) > remaining:
            parts.append(banner + source.content[:remaining] + "\n// [truncated]\n")
            break
        parts.append(chunk)
        used += len(chunk)
    return "\n".join(parts)


def contract_source_bundle(contract: FetchedContract, max_chars: int) -> str:
    """Format proxy + implementation sources for an LLM prompt."""
    sections = [
        format_sources_for_llm(
            contract.source_files,
            max_chars=max_chars // 2 if contract.implementation else max_chars,
            header=(
                f"// Contract {contract.name} at {contract.address}"
                + (" (proxy)" if contract.is_proxy else "")
            ),
        )
    ]
    if contract.implementation:
        sections.append(
            format_sources_for_llm(
                contract.implementation.source_files,
                max_chars=max_chars // 2,
                header=(
                    f"// Implementation {contract.implementation.name} "
                    f"at {contract.implementation.address}"
                ),
            )
        )
    return "\n\n".join(sections)


def slugify(title: str, index: int) -> str:
    """Stable-ish id for a finding title."""
    cleaned = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    cleaned = cleaned or "finding"
    return f"{index:02d}-{cleaned[:48]}"
