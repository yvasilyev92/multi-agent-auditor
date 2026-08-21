"""Pydantic models shared across tools, agents, and the UI."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"
    STATIC_ONLY = "static_only"


SeverityLiteral = Literal["Critical", "High", "Medium", "Low"]


class SourceFile(BaseModel):
    """One reconstructed Solidity (or JSON) file from Etherscan."""

    path: str
    content: str


class FetchedContract(BaseModel):
    """Verified source and metadata for one on-chain contract."""

    address: str
    name: str
    compiler_version: str
    source_files: list[SourceFile]
    remappings: list[str] = Field(default_factory=list)
    abi: str = ""
    is_proxy: bool = False
    implementation_address: str | None = None
    workdir: str = ""
    constructor_arguments: str = ""
    proxy_hint: str = ""

    # Nested so reports can show both proxy and implementation.
    implementation: FetchedContract | None = None


class SlitherFinding(BaseModel):
    """One detector result parsed from Slither JSON."""

    check: str
    impact: str
    confidence: str
    description: str
    elements: list[dict[str, Any]] = Field(default_factory=list)
    lines: list[int] = Field(default_factory=list)
    filenames: list[str] = Field(default_factory=list)


class Candidate(BaseModel):
    """A triaged vulnerability the pipeline may try to confirm with a PoC."""

    id: str
    title: str
    severity: Severity
    rationale: str
    category: str = ""
    target_functions: list[str] = Field(default_factory=list)
    related_slither_checks: list[str] = Field(default_factory=list)


class ExploitAttempt(BaseModel):
    """One generated Foundry test and its run outcome."""

    attempt: int
    test_code: str
    passed: bool
    stdout: str = ""
    stderr: str = ""
    revert_reason: str | None = None
    compile_error: bool = False


class Finding(BaseModel):
    """Final finding after optional PoC confirmation."""

    candidate: Candidate
    status: FindingStatus
    attempts: list[ExploitAttempt] = Field(default_factory=list)
    poc_code: str | None = None
    remediation: str = ""

    @property
    def status_label(self) -> str:
        if self.status is FindingStatus.CONFIRMED:
            return "CONFIRMED via PoC"
        if self.status is FindingStatus.UNCONFIRMED:
            return "unconfirmed"
        return "static-only"


class AuditResult(BaseModel):
    """Full pipeline output consumed by the UI, report agent, and eval."""

    address: str
    contract_name: str
    fork_block: int | None = None
    is_proxy: bool = False
    implementation_address: str | None = None
    proxy_hint: str = ""
    slither_findings: list[SlitherFinding] = Field(default_factory=list)
    slither_error: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    report_markdown: str = ""
    source_file_count: int = 0


# --- LLM structured-output schemas (no defaults; OpenAI json_schema-friendly) ---


class TriageCandidateSchema(BaseModel):
    """Schema the triage LLM must return for each candidate."""

    title: str = Field(description="Short vulnerability title")
    severity: SeverityLiteral = Field(description="Assigned severity")
    rationale: str = Field(description="Why this is a real issue, 2-4 sentences")
    category: str = Field(
        description="One of: reentrancy, access_control, oracle, accounting, invariant, other"
    )
    target_functions: list[str] = Field(description="Function names involved")
    related_slither_checks: list[str] = Field(
        description="Slither detector names this overlaps, or empty"
    )
    remediation: str = Field(description="Concrete remediation guidance")


class TriageOutputSchema(BaseModel):
    """Top-level structured output for the triage agent."""

    summary: str = Field(description="One-paragraph overview of the contract's risk")
    candidates: list[TriageCandidateSchema]


class ExploitOutputSchema(BaseModel):
    """Structured output for a generated Foundry exploit test."""

    test_code: str = Field(description="Complete Solidity Foundry test file contents")
    explanation: str = Field(description="What the PoC does and what passing proves")
    expected_outcome: str = Field(
        description="Concrete assertion that indicates a successful exploit"
    )


class ReportOutputSchema(BaseModel):
    """Structured output for the markdown audit report."""

    markdown: str = Field(description="Full markdown audit report")
