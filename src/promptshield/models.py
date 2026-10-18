"""Core data models shared across PromptShield (attacks, responses, findings, results)."""

from __future__ import annotations

import json
import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from promptshield.owasp import OWASP_LLM_TOP10

# --------------------------------------------------------------------------- enums


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHT[self]

    @property
    def rank(self) -> int:
        """Higher means more severe (used for sorting and ``--severity`` filtering)."""
        return self.weight


_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


class Category(StrEnum):
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    DATA_EXFILTRATION = "data_exfiltration"
    JAILBREAK = "jailbreak"
    EXCESSIVE_AGENCY = "excessive_agency"
    INSECURE_OUTPUT = "insecure_output"

    @property
    def label(self) -> str:
        return _CATEGORY_LABEL[self]

    @property
    def id_prefix(self) -> str:
        return _CATEGORY_PREFIX[self]


_CATEGORY_LABEL: dict[Category, str] = {
    Category.DIRECT_INJECTION: "Direct prompt injection",
    Category.INDIRECT_INJECTION: "Indirect injection (RAG)",
    Category.SYSTEM_PROMPT_LEAKAGE: "System-prompt leakage",
    Category.DATA_EXFILTRATION: "Sensitive-data exfiltration",
    Category.JAILBREAK: "Jailbreak / roleplay bypass",
    Category.EXCESSIVE_AGENCY: "Excessive agency (tool misuse)",
    Category.INSECURE_OUTPUT: "Insecure output handling",
}

_CATEGORY_PREFIX: dict[Category, str] = {
    Category.DIRECT_INJECTION: "DI",
    Category.INDIRECT_INJECTION: "II",
    Category.SYSTEM_PROMPT_LEAKAGE: "SL",
    Category.DATA_EXFILTRATION: "DX",
    Category.JAILBREAK: "JB",
    Category.EXCESSIVE_AGENCY: "EA",
    Category.INSECURE_OUTPUT: "IO",
}


class Verdict(StrEnum):
    PASS = "pass"  # the target resisted the attack
    FAIL = "fail"  # the attack succeeded
    ERROR = "error"  # the target could not be reached / returned garbage
    SKIPPED = "skipped"  # no detector could be evaluated (e.g. no canary configured)


# --------------------------------------------------------------------------- target I/O


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class TargetRequest(BaseModel):
    """What PromptShield sends to a target for one attack."""

    message: str
    documents: list[str] = Field(default_factory=list)


class TargetResponse(BaseModel):
    """What a target answered. ``tool_calls`` is filled when the target reports them."""

    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)

    @property
    def searchable_text(self) -> str:
        """Reply text plus serialised tool calls, so leaks via tool arguments are caught too."""
        if not self.tool_calls:
            return self.text
        calls = " ".join(
            f"{c.name}({json.dumps(c.arguments, default=str, ensure_ascii=False)})"
            for c in self.tool_calls
        )
        return f"{self.text}\n{calls}"


# --------------------------------------------------------------------------- detector specs


def _checked_regex(pattern: str) -> str:
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid regular expression {pattern!r}: {exc}") from exc
    return pattern


class _Spec(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CanarySpec(_Spec):
    """Fails if any configured secret (canary token, planted credentials...) shows up."""

    type: Literal["canary"] = "canary"


class MarkerSpec(_Spec):
    """Fails if the response contains an attacker-chosen marker (proof of hijacking)."""

    type: Literal["marker"] = "marker"
    value: str = Field(min_length=4)
    refusal_aware: bool = True


class RegexSpec(_Spec):
    type: Literal["regex"] = "regex"
    pattern: str
    description: str

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, v: str) -> str:
        return _checked_regex(v)


class PromptLeakSpec(_Spec):
    """Fails if the response repeats a run of ``min_words`` words from the system prompt."""

    type: Literal["prompt_leak"] = "prompt_leak"
    min_words: int = Field(default=8, ge=4, le=60)


UnsafeKind = Literal[
    "script_tag",
    "event_handler",
    "javascript_url",
    "html_embed",
    "markdown_image_exfil",
    "sql_tautology",
    "shell_pipe",
]


class UnsafeOutputSpec(_Spec):
    """Fails if the response contains active/dangerous content a downstream sink might run."""

    type: Literal["unsafe_output"] = "unsafe_output"
    kinds: list[UnsafeKind] = Field(min_length=1)


class ToolCallSpec(_Spec):
    """Fails if the target invokes one of ``tools`` (optionally with matching arguments)."""

    type: Literal["tool_call"] = "tool_call"
    tools: list[str] = Field(min_length=1)
    arg_pattern: str | None = None
    text_pattern: str | None = None  # fallback for targets that don't report tool calls

    @field_validator("arg_pattern", "text_pattern")
    @classmethod
    def _compiles(cls, v: str | None) -> str | None:
        return None if v is None else _checked_regex(v)


DetectorSpec = Annotated[
    CanarySpec | MarkerSpec | RegexSpec | PromptLeakSpec | UnsafeOutputSpec | ToolCallSpec,
    Field(discriminator="type"),
]

# --------------------------------------------------------------------------- attacks

_ATTACK_ID = re.compile(r"^(DI|II|SL|DX|JB|EA|IO)-\d{3}$")


class Attack(BaseModel):
    """One test case from the attack library (a YAML entry)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str = Field(min_length=3)
    category: Category
    owasp: str
    related_owasp: list[str] = Field(default_factory=list)
    severity: Severity
    explanation: str = Field(min_length=20)
    prompt: str = Field(min_length=1)
    documents: list[str] = Field(default_factory=list)
    detectors: list[DetectorSpec] = Field(min_length=1)
    fix: str = Field(min_length=20)
    tags: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _ATTACK_ID.match(v):
            raise ValueError("id must look like 'DI-001' (two-letter category prefix + 3 digits)")
        return v

    @field_validator("owasp")
    @classmethod
    def _valid_owasp(cls, v: str) -> str:
        if v not in OWASP_LLM_TOP10:
            raise ValueError(f"unknown OWASP LLM code {v!r}; expected one of LLM01..LLM10")
        return v

    @field_validator("related_owasp")
    @classmethod
    def _valid_related(cls, v: list[str]) -> list[str]:
        for code in v:
            if code not in OWASP_LLM_TOP10:
                raise ValueError(f"unknown OWASP LLM code {code!r}")
        return v

    @model_validator(mode="after")
    def _prefix_matches_category(self) -> Attack:
        if not self.id.startswith(self.category.id_prefix + "-"):
            raise ValueError(
                f"id {self.id!r} must start with {self.category.id_prefix!r} "
                f"for category {self.category.value!r}"
            )
        return self


# --------------------------------------------------------------------------- results


class DetectorHit(BaseModel):
    detector: str
    reason: str
    evidence: str = ""


class JudgeVerdict(BaseModel):
    """Advisory opinion of the optional LLM-as-judge. Never changes the deterministic verdict."""

    label: Literal["suspicious", "clean", "unknown"]
    confidence: float | None = None
    reason: str = ""


class Finding(BaseModel):
    attack: Attack
    verdict: Verdict
    request: TargetRequest
    response: TargetResponse | None = None
    hits: list[DetectorHit] = Field(default_factory=list)
    judge: JudgeVerdict | None = None
    error: str | None = None
    skipped_reason: str | None = None
    latency_ms: int = 0


class CategoryScore(BaseModel):
    category: Category
    label: str
    score: float | None
    passed: int
    failed: int
    other: int  # errors + skipped


class OwaspScore(BaseModel):
    code: str
    title: str
    score: float | None
    passed: int
    failed: int
    other: int


class TargetInfo(BaseModel):
    type: str
    name: str
    description: str


class ScanResult(BaseModel):
    tool: str = "promptshield"
    version: str
    author: str
    author_url: str
    started_at: datetime
    finished_at: datetime
    target: TargetInfo
    attestation: str
    score: float | None
    grade: str
    total: int
    passed: int
    failed: int
    errors: int
    skipped: int
    categories: list[CategoryScore]
    owasp: list[OwaspScore]
    findings: list[Finding]
    judge_enabled: bool = False
    judge_model: str | None = None
    judge_flagged: int = 0
    notes: list[str] = Field(default_factory=list)
