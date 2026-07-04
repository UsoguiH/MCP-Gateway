"""Authorization engine — ABAC + tier + taint (spec §4.1/§5, closes v7 flaw B5 controls).

Pure decision function: given the caller's claims, the tool's registry entry, the
requested arguments, and any taint hits, decide whether the call is DENIED,
ALLOWED (auto), or requires approval (HITL tier 2 or 3). No I/O here so it is
trivially unit-testable.
"""
from dataclasses import dataclass, field

from .config import POLICY, clearance_rank


@dataclass
class Decision:
    outcome: str            # "deny" | "allow" | "approve"
    tier: int
    reason: str
    approvals_required: int = 0
    taint: list = field(default_factory=list)
    flags: list = field(default_factory=list)


def decide(claims: dict, entry: dict | None, arguments: dict,
           taint_hits: list, unicode_flags: list) -> Decision:
    role = claims.get("role", "")
    role_cfg = POLICY["roles"].get(role)
    if not role_cfg:
        return Decision("deny", 0, f"unknown role '{role}'")

    if entry is None:
        return Decision("deny", 0, "tool not in registry")
    if entry["status"] != "active":
        return Decision("deny", entry["tier"],
                        f"tool quarantined ({entry.get('quarantine_reason')})")

    tier = entry["tier"]

    # Taint escalation: a tainted argument can never auto-execute a write.
    effective_tier = tier
    if taint_hits and tier <= 1:
        effective_tier = 2
    if taint_hits and tier >= 2:
        effective_tier = max(effective_tier, tier)  # stays, but flagged in preview

    # Role ceiling: may the role invoke a tool of this tier at all?
    if effective_tier > role_cfg["max_tool_tier"]:
        return Decision("deny", effective_tier,
                        f"tier {effective_tier} exceeds role ceiling {role_cfg['max_tool_tier']}",
                        taint=taint_hits, flags=unicode_flags)

    if effective_tier <= 0:
        return Decision("allow", effective_tier, "read-only auto-allowed",
                        taint=taint_hits, flags=unicode_flags)
    if effective_tier == 1 and not taint_hits:
        return Decision("allow", 1, "reversible write, policy auto-approved",
                        taint=taint_hits, flags=unicode_flags)

    approvals = 2 if effective_tier >= 3 else 1
    reason = "requires human approval"
    if taint_hits:
        reason = "tainted argument -> human approval required"
    return Decision("approve", effective_tier, reason,
                    approvals_required=approvals, taint=taint_hits, flags=unicode_flags)


def clearance_allows(claims: dict, classification: str) -> bool:
    """True if the caller's clearance dominates the data classification."""
    return clearance_rank(claims.get("clearance", "public")) >= clearance_rank(classification)
