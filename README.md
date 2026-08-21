# Multi-Agent Smart Contract Auditor

Defensive Ethereum audit tool. It fetches verified source, runs Slither, triages findings with an LLM, then **confirms** Critical/High issues only when a generated Foundry exploit **test** passes on a **local mainnet fork**.

Nothing is ever broadcast to the live chain. A passing PoC is strong evidence, not a substitute for human review.

## How confirmation works

1. **Fetch** verified Solidity from Etherscan (flattened or standard-json-input). Follow EIP-1967 proxies and audit the implementation too.
2. **Static analysis** — pick the matching `solc` via `solc-select`, run `slither --json`.
3. **Triage** (LLM) — dedupe Slither results and add business-logic candidates (access control, oracles, accounting, invariants).
4. **Exploit confirmation** (LLM + Foundry) — for each Critical/High candidate, generate a fork test (`vm.prank`, `vm.deal`, …). If it reverts or an assertion fails, retry up to `MAX_RETRIES` (default 3). **CONFIRMED** only if the test passes.
5. **Report** — markdown with severity, status (`CONFIRMED via PoC` / unconfirmed / static-only), passing PoC, and remediation.

## Prerequisites and setup

Do these in order.

### 1. Install Foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Confirm `forge` and `cast` are on your `PATH`.

### 2. Install uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 3. Install solc-select (standalone CLI)

solc versions are installed on demand at runtime. Install the CLI onto your `PATH` with:

```bash
uv tool install solc-select
```

### 4. Install Python dependencies

From this repository (Python 3.11+ is pinned in `pyproject.toml`):

```bash
uv sync
```

This creates the environment and installs every Python package from `pyproject.toml`. There is no `requirements.txt`.

### 5. Configure secrets

```bash
cp .env.example .env
```

Fill in:

```
OPENAI_API_KEY=
ETHERSCAN_API_KEY=
INFURA_URL=https://mainnet.infura.io/v3/<key>
```

`INFURA_URL` is any Ethereum HTTPS RPC used as `forge --fork-url` (Infura, Alchemy, etc.).

Optional overrides: `OPENAI_MODEL` (default `gpt-4o`), `MAX_RETRIES` (default `3`), `DEFAULT_FORK_BLOCK`, `LOG_LEVEL`.

### 6. Run the app

```bash
uv run streamlit run app.py
```

Paste a verified mainnet address, optionally pin a fork block, and click **Audit**.

### 7. Tests

Fast unit tests (no RPC, no LLM):

```bash
uv run pytest tests/unit
```

Fixture eval (default): start a local Anvil **mainnet fork**, deploy three intentionally vulnerable contracts with a Foundry script (`--broadcast` goes to Anvil only — no live Ethereum, no ETH spent), run known-good reference exploits, then run the full auditor pipeline (LLM triage + Foundry PoC) against those addresses:

```bash
uv run python -m auditor.eval
# equivalent:
uv run python -m auditor.eval --fixtures
uv run python -m auditor.eval --all
```

Pick one (or several) of the three fixtures instead of all:

```bash
uv run python -m auditor.eval --contract ReentrancyVault
uv run python -m auditor.eval --contract reentrancy
uv run python -m auditor.eval --contract OpenDrainWallet --contract SpotOracleLender
```

Names: `ReentrancyVault` (aliases: reentrancy, vault), `OpenDrainWallet` (opendrain, drain, wallet), `SpotOracleLender` (oracle, spot, lender).

Historical mainnet cases (Beanstalk, Euler, USDC control), fork pinned to just before each exploit:

```bash
uv run python -m auditor.eval --historical
uv run python -m auditor.eval --historical --only beanstalk
```

Each eval writes the LLM markdown report for every contract into a new timestamped folder:

```
test-pipeline-llm-reports/<YYYY-MM-DDTHH-MM-SS>/<ContractName>.md
```

The path is printed in the scorecard. That directory is gitignored.

## Layout

```
app.py                     Streamlit entry
auditor/
  config.py                models, retries, timeouts, secrets
  models.py                Pydantic types
  orchestrator.py          sequential pipeline + PoC retry loop
  agents/                  LCEL structured-output chains (no LangGraph)
  tools/                   Etherscan, Slither, Foundry (subprocess)
  ui/                      Streamlit page
  eval.py                  scorecard CLI
  anvil.py                 local mainnet-fork process
  fixture_eval.py          deploy fixtures + score auditor
fixtures/                  Foundry project with intentional vulns
tests/unit/                pytest (parsers, no network)
```

LangChain is used only for the LLM steps (`ChatOpenAI.with_structured_output`). Fetching, Slither, and Forge are plain Python tools.

## Robustness notes

- Etherscan calls retry with backoff on rate limits; unverified contracts fail with a clear error.
- Every subprocess has a timeout; stdout and stderr are captured.
- Slither / Forge JSON parsing is defensive — if a tool changes shape, the pipeline degrades instead of crashing.
- If Slither fails, triage still runs against source.
- If the report LLM fails, a template markdown report is used.
- Fixture eval injects Solidity from `fixtures/src/` (Etherscan will not know those addresses) and points Foundry at the Anvil RPC so PoCs see the simulated deploys.

## Disclaimer

This is an automated first-pass auditor. Confirmed findings should still be reviewed by a human before any production decision. All exploit tests execute solely against a local forked EVM.
