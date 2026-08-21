"""User-facing and internal errors for the auditor pipeline."""


class AuditorError(Exception):
    """Recoverable audit error that should be shown in the UI."""


class InvalidAddressError(AuditorError):
    """The provided value is not a 20-byte Ethereum address."""


class UnverifiedSourceError(AuditorError):
    """Etherscan has no verified source for this address."""


class RateLimitError(AuditorError):
    """Etherscan (or RPC) rate-limited the request after retries."""


class ToolNotFoundError(AuditorError):
    """A required CLI (forge, slither, solc-select) is missing from PATH."""


class ToolTimeoutError(AuditorError):
    """A subprocess exceeded its timeout."""


class ToolCommandError(AuditorError):
    """A subprocess exited unsuccessfully."""
