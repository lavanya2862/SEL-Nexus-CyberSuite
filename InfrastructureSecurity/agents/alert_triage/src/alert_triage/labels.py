"""The words Alert Triage shows for its verdicts: Microsoft Defender's own classification terms (chosen 5 Oct 2026), each with
a plain-English hint. Internal codes (likely_true_positive, ...) never change; only these display words do.
The portal shows these words as they come in Alert Triage's exported data.
"""

VERDICT_LABEL = {
    "likely_true_positive": "True positive",
    "benign_positive": "Informational, expected activity",
    "likely_false_positive": "False positive",
    "needs_investigation": "Needs review",
}
VERDICT_HINT = {
    "likely_true_positive": "a real attack",
    "benign_positive": "real activity, but allowed (e.g. a test or an approved admin)",
    "likely_false_positive": "the alarm was wrong, nothing happened",
    "needs_investigation": "an analyst decides",
}


def label(code: str | None) -> str:
    return VERDICT_LABEL.get(code or "", str(code or "-").replace("_", " "))
