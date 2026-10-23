"""Answer formats Gemini must follow (JSON schema). Kept simple so the API's schema support covers them."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Product(BaseModel):
    vendor: str = Field(description="Vendor name, e.g. 'Citrix'")
    product: str = Field(description="Product name, e.g. 'NetScaler ADC'")
    versions: str = Field(description="Affected versions as written in the source, or '' if not stated")


class Technique(BaseModel):
    id: str = Field(description="MITRE ATT&CK Enterprise technique ID, e.g. 'T1190' or 'T1059.001'")
    reason: str = Field(description="Which part of the source shows this technique (max 20 words)")


class Indicator(BaseModel):
    type: str = Field(description="One of: ip, domain, url, sha256, sha1, md5")
    value: str = Field(description="The indicator exactly as written in the source (refanged)")


class ThreatAnalysis(BaseModel):
    summary: str = Field(description="Plain-English summary for a non-expert manager, max 80 words")
    threat_type: str = Field(description="One of: vulnerability, malware, phishing, campaign, indicator_list, advisory, other")
    exploited_in_wild: str = Field(description="yes, no or unknown, based only on the source")
    cves: list[str] = Field(description="CVE IDs mentioned in the source")
    products: list[Product] = Field(description="Affected products named in the source (max 10)")
    techniques: list[Technique] = Field(description="ATT&CK techniques clearly supported by the source (max 6)")
    indicators: list[Indicator] = Field(description="IOCs (IPs, domains, URLs, hashes) listed in the source (max 50)")
    actions: list[str] = Field(description="Up to 5 concrete recommended actions (patch to version X, block Y...)")
    confidence: str = Field(description="high, medium or low: how clear the source is")


class KqlDraft(BaseModel):
    query: str = Field(description="One read-only KQL query for Microsoft Defender Advanced Hunting")
    explanation: str = Field(description="What the query looks for, max 40 words")


class ExecutiveSummary(BaseModel):
    headline: str = Field(description="One sentence: the most important message")
    paragraphs: list[str] = Field(description="2-3 short paragraphs for a non-expert manager")
    top_actions: list[str] = Field(description="Up to 5 actions, most urgent first")


class Resolution(BaseModel):
    what_happened: str = Field(description="What this sign of attack means, in plain English for a non-expert, max 40 words")
    steps: list[str] = Field(description="3 to 6 resolution steps in order, each one concrete action starting with a verb, max 35 words each")
    done_when: str = Field(description="How to confirm the problem is resolved, max 30 words")


class FixAdvice(BaseModel):
    steps: list[str] = Field(description="3 to 6 steps in order to remove this threat from our computers, each one concrete action starting with a verb, max 35 words each")
    done_when: str = Field(description="How to confirm the threat no longer affects us, max 30 words")
