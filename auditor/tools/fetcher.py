"""FetcherTool: pull verified source from Etherscan and detect EIP-1967 proxies."""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

import httpx

from auditor.config import (
    CHAIN_ID,
    EIP1967_IMPLEMENTATION_SLOT,
    ETHERSCAN_BASE_URL,
    get_settings,
)
from auditor.errors import AuditorError, RateLimitError, UnverifiedSourceError
from auditor.models import FetchedContract, SourceFile
from auditor.util import storage_slot_to_address, validate_address

logger = logging.getLogger(__name__)

_PROXY_NAME_RE = re.compile(r"proxy|upgradeable|eip1967", re.IGNORECASE)
_MAX_RETRIES = 5


class FetcherTool:
    """Download verified source, reconstruct files, and follow proxy implementations."""

    def __init__(self) -> None:
        self._settings = get_settings()

    def load_local(
        self,
        address: str,
        source_path: str | Path,
        dest: str | Path,
    ) -> FetchedContract:
        """Build a FetchedContract from a local .sol file or directory (no Etherscan)."""
        checksum = validate_address(address)
        dest_dir = Path(dest)
        dest_dir.mkdir(parents=True, exist_ok=True)
        files = _read_local_sources(Path(source_path))
        written = write_sources(dest_dir, files)
        name = _guess_contract_name(written)
        logger.info("Loaded local source for %s (%s, %s file(s))", checksum, name, len(written))
        return FetchedContract(
            address=checksum,
            name=name,
            compiler_version="v0.8.24+commit.e11b9ed9",
            source_files=written,
            workdir=str(dest_dir),
            proxy_hint="Loaded from local fixture source (not Etherscan).",
        )

    def fetch(self, address: str, workdir: str | Path, *, fork_block: int | None = None) -> FetchedContract:
        """Fetch ``address`` (and its implementation, if any) into ``workdir``."""
        checksum = validate_address(address)
        root = Path(workdir)
        root.mkdir(parents=True, exist_ok=True)

        contract = self._fetch_one(checksum, root / "proxy_or_target")
        impl_addr = self._resolve_implementation(contract, fork_block=fork_block)
        if impl_addr and impl_addr != contract.address:
            logger.info("Proxy detected; fetching implementation %s", impl_addr)
            try:
                implementation = self._fetch_one(impl_addr, root / "implementation")
            except UnverifiedSourceError:
                logger.warning("Implementation %s is not verified; auditing proxy source only", impl_addr)
                contract.is_proxy = True
                contract.implementation_address = impl_addr
                contract.proxy_hint = (
                    contract.proxy_hint
                    + f" Implementation {impl_addr} is unverified; audited proxy source only."
                ).strip()
                return contract
            contract.is_proxy = True
            contract.implementation_address = implementation.address
            contract.implementation = implementation
            if not contract.proxy_hint:
                contract.proxy_hint = (
                    f"EIP-1967/Etherscan proxy {contract.address} → implementation {implementation.address}"
                )
        return contract

    def _fetch_one(self, address: str, dest: Path) -> FetchedContract:
        payload = self._etherscan_getsourcecode(address)
        source_code = (payload.get("SourceCode") or "").strip()
        if not source_code or payload.get("ABI") == "Contract source code not verified":
            raise UnverifiedSourceError(
                f"Contract {address} is not verified on Etherscan. "
                "This tool can only audit verified source."
            )

        compiler = payload.get("CompilerVersion") or ""
        if compiler.lower().startswith("vyper"):
            raise AuditorError(
                f"Contract {address} is verified as Vyper ({compiler}). "
                "This auditor currently supports Solidity only."
            )

        name = payload.get("ContractName") or "Contract"
        files, remappings = parse_source_code(source_code, default_filename=f"{name}.sol")
        dest.mkdir(parents=True, exist_ok=True)
        written = write_sources(dest, files)
        if remappings:
            (dest / "remappings.txt").write_text("\n".join(remappings) + "\n", encoding="utf-8")

        etherscan_proxy = str(payload.get("Proxy") or "") == "1"
        etherscan_impl = (payload.get("Implementation") or "").strip()
        etherscan_impl_addr = None
        if etherscan_impl and etherscan_impl != "0x" + "0" * 40:
            try:
                etherscan_impl_addr = validate_address(etherscan_impl)
            except Exception:
                etherscan_impl_addr = None

        hint_parts: list[str] = []
        if etherscan_proxy:
            hint_parts.append("Etherscan marked this contract as a proxy")
        if etherscan_impl_addr:
            hint_parts.append(f"Etherscan implementation field = {etherscan_impl_addr}")

        looks_like_proxy = etherscan_proxy or bool(_PROXY_NAME_RE.search(name)) or _source_mentions_eip1967(files)

        return FetchedContract(
            address=address,
            name=name,
            compiler_version=compiler,
            source_files=written,
            remappings=remappings,
            abi=payload.get("ABI") or "",
            is_proxy=looks_like_proxy,
            implementation_address=etherscan_impl_addr,
            workdir=str(dest),
            constructor_arguments=payload.get("ConstructorArguments") or "",
            proxy_hint="; ".join(hint_parts),
        )

    def _etherscan_getsourcecode(self, address: str) -> dict[str, Any]:
        params = {
            "chainid": str(CHAIN_ID),
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self._settings.etherscan_api_key,
        }
        data = self._etherscan_get(params)
        status = str(data.get("status", ""))
        result = data.get("result")
        if status != "1" or not result:
            message = result if isinstance(result, str) else data.get("message") or "unknown Etherscan error"
            raise AuditorError(f"Etherscan getsourcecode failed for {address}: {message}")
        if not isinstance(result, list) or not result:
            raise AuditorError(f"Unexpected Etherscan getsourcecode shape for {address}")
        first = result[0]
        if not isinstance(first, dict):
            raise AuditorError(f"Unexpected Etherscan result item for {address}")
        return first

    def _etherscan_get(self, params: dict[str, str]) -> dict[str, Any]:
        delay = 1.0
        last_error = "unknown"
        timeout = httpx.Timeout(self._settings.etherscan_timeout_s)
        with httpx.Client(timeout=timeout) as client:
            for attempt in range(1, _MAX_RETRIES + 1):
                try:
                    response = client.get(ETHERSCAN_BASE_URL, params=params)
                except httpx.HTTPError as exc:
                    last_error = str(exc)
                    logger.warning("Etherscan request error (attempt %s): %s", attempt, exc)
                    time.sleep(delay)
                    delay = min(delay * 2, 16)
                    continue

                body_preview = response.text[:500]
                if response.status_code == 429 or _looks_like_rate_limit(body_preview):
                    last_error = f"HTTP {response.status_code}: {body_preview}"
                    logger.warning("Etherscan rate limit (attempt %s); sleeping %.1ss", attempt, delay)
                    time.sleep(delay)
                    delay = min(delay * 2, 16)
                    continue

                try:
                    response.raise_for_status()
                    data = response.json()
                except (httpx.HTTPError, json.JSONDecodeError) as exc:
                    last_error = str(exc)
                    logger.warning("Etherscan parse/HTTP error (attempt %s): %s", attempt, exc)
                    time.sleep(delay)
                    delay = min(delay * 2, 16)
                    continue

                result = data.get("result")
                if data.get("status") == "0" and _looks_like_rate_limit(str(result)):
                    last_error = str(result)
                    logger.warning("Etherscan rate-limit body (attempt %s); sleeping %.1ss", attempt, delay)
                    time.sleep(delay)
                    delay = min(delay * 2, 16)
                    continue
                return data

        raise RateLimitError(
            f"Etherscan still rate-limiting or unreachable after {_MAX_RETRIES} attempts: {last_error}"
        )

    def _resolve_implementation(
        self, contract: FetchedContract, *, fork_block: int | None
    ) -> str | None:
        """Prefer the EIP-1967 storage slot; fall back to Etherscan's Implementation field."""
        slot_addr = self._read_eip1967_implementation(contract.address, fork_block=fork_block)
        if slot_addr:
            logger.info("EIP-1967 implementation slot → %s", slot_addr)
            if not contract.proxy_hint:
                contract.proxy_hint = f"EIP-1967 slot at {contract.address} → {slot_addr}"
            else:
                contract.proxy_hint += f"; EIP-1967 slot → {slot_addr}"
            return slot_addr
        if contract.implementation_address:
            return contract.implementation_address
        if contract.is_proxy:
            logger.info("Contract looks like a proxy but implementation slot was empty")
        return None

    def _read_eip1967_implementation(self, address: str, *, fork_block: int | None) -> str | None:
        block_tag = hex(fork_block) if fork_block is not None else "latest"
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getStorageAt",
            "params": [address, EIP1967_IMPLEMENTATION_SLOT, block_tag],
        }
        timeout = httpx.Timeout(self._settings.rpc_timeout_s)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(self._settings.infura_url, json=payload)
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            logger.warning("eth_getStorageAt failed for %s: %s", address, exc)
            return None
        if isinstance(data, dict) and data.get("error"):
            logger.warning("eth_getStorageAt RPC error for %s: %s", address, data["error"])
            return None
        return storage_slot_to_address(str((data or {}).get("result") or ""))


def _read_local_sources(source_path: Path) -> dict[str, str]:
    if not source_path.exists():
        raise AuditorError(f"Local source path does not exist: {source_path}")
    files: dict[str, str] = {}
    if source_path.is_file():
        files[source_path.name] = source_path.read_text(encoding="utf-8")
        return files
    for path in sorted(source_path.rglob("*")):
        if path.is_file() and path.suffix == ".sol":
            rel = path.relative_to(source_path)
            files[str(rel)] = path.read_text(encoding="utf-8")
    if not files:
        raise AuditorError(f"No .sol files found under {source_path}")
    return files


def _guess_contract_name(files: list[SourceFile]) -> str:
    contract_re = re.compile(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)")
    for source in files:
        match = contract_re.search(source.content)
        if match:
            return match.group(1)
    if files:
        return Path(files[0].path).stem
    return "Contract"


def parse_source_code(source_code: str, *, default_filename: str) -> tuple[dict[str, str], list[str]]:
    """Handle flat Solidity, double-wrapped JSON, and standard-json-input."""
    raw = source_code.strip()
    if not raw:
        return {}, []

    candidate = raw
    if candidate.startswith("{{") and candidate.endswith("}}"):
        candidate = candidate[1:-1]

    try:
        parsed: Any = json.loads(candidate)
    except json.JSONDecodeError:
        return {default_filename: source_code}, []

    if not isinstance(parsed, dict):
        return {default_filename: source_code}, []

    remappings: list[str] = []
    files: dict[str, str] = {}

    sources = parsed.get("sources")
    if isinstance(sources, dict):
        settings = parsed.get("settings") if isinstance(parsed.get("settings"), dict) else {}
        remappings = [str(item) for item in (settings.get("remappings") or []) if item]
        for path, meta in sources.items():
            content = _meta_content(meta)
            if content is not None:
                files[str(path)] = content
        if files:
            return files, remappings

    # Older Etherscan multi-file: { "Foo.sol": { "content": "..." } }
    if parsed and all(isinstance(v, dict) and "content" in v for v in parsed.values()):
        for path, meta in parsed.items():
            content = _meta_content(meta)
            if content is not None:
                files[str(path)] = content
        return files, remappings

    return {default_filename: source_code}, []


def _meta_content(meta: Any) -> str | None:
    if isinstance(meta, str):
        return meta
    if isinstance(meta, dict) and "content" in meta:
        return str(meta.get("content") or "")
    return None


def write_sources(dest: Path, files: dict[str, str]) -> list[SourceFile]:
    """Write reconstructed files under ``dest``, rejecting ``..`` path segments."""
    written: list[SourceFile] = []
    for raw_path, content in files.items():
        rel = _safe_relpath(raw_path)
        full = dest / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
        written.append(SourceFile(path=str(rel), content=content))
        logger.debug("Wrote source %s (%s bytes)", full, len(content))
    if not written:
        raise UnverifiedSourceError("Verified source payload contained no files")
    return written


def _safe_relpath(path: str) -> Path:
    normalized = path.replace("\\", "/").lstrip("/")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts or ".." in parts:
        # Flatten unsafe paths to a single filename so reconstruction still works.
        name = parts[-1] if parts else "Contract.sol"
        return Path(name.replace("..", "_"))
    return Path(*parts)


def _source_mentions_eip1967(files: dict[str, str]) -> bool:
    needle = EIP1967_IMPLEMENTATION_SLOT.lower()
    return any(needle in content.lower() or "eip1967" in content.lower() for content in files.values())


def _looks_like_rate_limit(text: str) -> bool:
    lowered = text.lower()
    return any(
        token in lowered
        for token in ("rate limit", "max rate", "too many requests", "429")
    )
