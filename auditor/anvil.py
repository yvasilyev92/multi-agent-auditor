"""Start a local Anvil mainnet fork and tear it down cleanly."""

from __future__ import annotations

import logging
import socket
import subprocess
import time
from dataclasses import dataclass

import httpx

from auditor.errors import AuditorError
from auditor.subprocess_utils import which

logger = logging.getLogger(__name__)

# Well-known Anvil account 0. Never use this key on a live network.
ANVIL_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


@dataclass
class AnvilInstance:
    """A running Anvil process bound to a local port."""

    url: str
    port: int
    process: subprocess.Popen[str]

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        logger.info("Anvil on port %s stopped", self.port)


def start_anvil(fork_url: str, *, timeout_s: float = 60) -> AnvilInstance:
    """Spawn ``anvil --fork-url`` on an ephemeral port and wait until JSON-RPC answers."""
    anvil = which(
        "anvil",
        hint="Install Foundry: `curl -L https://foundry.paradigm.xyz | bash` then `foundryup`.",
    )
    port = _free_port()
    logger.info("Starting Anvil on 127.0.0.1:%s (forking %s)", port, _redact_url(fork_url))
    process = subprocess.Popen(
        [
            anvil,
            "--fork-url",
            fork_url,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + timeout_s
    last_error = "not started"
    while time.time() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise AuditorError(f"Anvil exited early (code {process.returncode}): {output[-2000:]}")
        try:
            with httpx.Client(timeout=2.0) as client:
                response = client.post(
                    url,
                    json={"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []},
                )
                response.raise_for_status()
                if response.json().get("result"):
                    logger.info("Anvil ready at %s", url)
                    return AnvilInstance(url=url, port=port, process=process)
        except Exception as exc:  # noqa: BLE001 — poll until timeout
            last_error = str(exc)
        time.sleep(0.4)
    process.kill()
    raise AuditorError(f"Anvil did not become ready within {timeout_s}s: {last_error}")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _redact_url(url: str) -> str:
    if len(url) > 48:
        return url[:32] + "…"
    return url
