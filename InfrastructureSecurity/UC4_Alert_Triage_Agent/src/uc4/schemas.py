"""The AI's answer format (feasibility guide Appendix C.7), checked with pydantic (as UC1 does).
`config/verdict.schema.json` documents the same contract for readers; this model is what the code enforces.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

VERDICTS = ("likely_true_positive", "likely_false_positive", "benign_positive", "needs_investigation")


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    source: str = Field(max_length=120)
    query_id: str = Field(default="", max_length=60)
    finding: str = Field(max_length=400)


class TriageVerdict(BaseModel):
    model_config = ConfigDict(extra="ignore")
    summary: str = Field(max_length=800)
    verdict: Literal["likely_true_positive", "likely_false_positive", "benign_positive", "needs_investigation"]
    confidence: Literal["low", "medium", "high"]
    recommended_severity: Literal["informational", "low", "medium", "high"]
    evidence: list[EvidenceItem] = Field(default_factory=list, max_length=20)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=12)
    recommended_actions: list[str] = Field(default_factory=list, max_length=8)
    containment_options: list[str] = Field(default_factory=list, max_length=6)
    escalate: bool = False
    guardrail_triggered: str = ""
    would_change_verdict_if: str = Field(default="", max_length=400)
