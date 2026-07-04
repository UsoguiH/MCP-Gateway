"""NDMO data classification propagation (blueprint Layer 6; Platform plan W3.3).

The four-level national scheme (aligned to `policy.yaml: clearance_order`):
    public < restricted < secret < top_secret

Every data-bearing tool has a **maximum classification** (from the registry, set at
onboarding). The gateway propagates that label onto each response and uses it as the
DLP unmask threshold: a caller may see fields in the clear only if their clearance
dominates the response's classification. Production data servers must call the same
label propagation on their outputs (part of the §10 interface contract).
"""
from .config import CLEARANCE_ORDER, clearance_rank

DEFAULT_CLASSIFICATION = "secret"   # fail-toward-protected for un-labelled tools


def is_valid(label: str) -> bool:
    return label in CLEARANCE_ORDER


def rank(label: str) -> int:
    return clearance_rank(label)


def dominates(clearance: str, classification: str) -> bool:
    """True if `clearance` is cleared to see data classified `classification`."""
    return rank(clearance) >= rank(classification)


def tool_classification(registry_entry: dict | None) -> str:
    """The maximum classification a tool's data may carry (registry-owned)."""
    if not registry_entry:
        return DEFAULT_CLASSIFICATION
    label = registry_entry.get("classification", DEFAULT_CLASSIFICATION)
    return label if is_valid(label) else DEFAULT_CLASSIFICATION
