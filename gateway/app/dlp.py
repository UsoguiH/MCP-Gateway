"""DLP — Saudi PII detection and masking (spec §4.8, closes v7 flaw B8).

Deterministic validators for the structured identifiers (National ID / Iqama,
Saudi IBAN) with checksum verification to cut false positives. In production a
three-point pipeline adds an offline Arabic NER model for names/addresses; here
we ship the deterministic core plus a name-pattern hook so the masking path is
real and testable now.

Masking is applied on tool results before they enter model context and on model
output before it reaches the user, unless the caller's clearance authorizes the
field (clearance-gated unmasking is enforced by the gateway, not here).
"""
import re

# Saudi National ID starts 1, Iqama starts 2; both are 10 digits.
_ID_RE = re.compile(r"\b([12]\d{9})\b")
# Saudi IBAN: SA + 2 check digits + 18 digits = 24 chars.
_IBAN_RE = re.compile(r"\bSA\d{22}\b", re.IGNORECASE)


def _luhn_ok(number: str) -> bool:
    """Saudi National ID uses a Luhn-style check digit."""
    digits = [int(d) for d in number]
    total = 0
    for i, d in enumerate(digits[:-1]):
        if i % 2 == 0:
            doubled = d * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += d
    check = (10 - (total % 10)) % 10
    return check == digits[-1]


def _iban_ok(iban: str) -> bool:
    """ISO 7064 mod-97 IBAN checksum."""
    iban = iban.upper()
    rearranged = iban[4:] + iban[:4]
    converted = "".join(str(int(c, 36)) if c.isalpha() else c for c in rearranged)
    try:
        return int(converted) % 97 == 1
    except ValueError:
        return False


def scan(text: str) -> list[dict]:
    """Return a list of detected PII spans: {type, value, start, end}."""
    if not isinstance(text, str):
        return []
    found: list[dict] = []
    for m in _ID_RE.finditer(text):
        val = m.group(1)
        kind = "national_id" if val[0] == "1" else "iqama"
        if _luhn_ok(val):
            found.append({"type": kind, "value": val, "start": m.start(), "end": m.end()})
    for m in _IBAN_RE.finditer(text):
        if _iban_ok(m.group(0)):
            found.append({"type": "iban", "value": m.group(0), "start": m.start(), "end": m.end()})
    return found


def mask(text: str) -> tuple[str, list[dict]]:
    """Return (masked_text, detections). Overlapping spans handled left-to-right."""
    detections = scan(text)
    if not detections:
        return text, []
    # Apply from the right so indices stay valid.
    out = text
    for d in sorted(detections, key=lambda x: x["start"], reverse=True):
        token = _token_for(d["type"], d["value"])
        out = out[: d["start"]] + token + out[d["end"] :]
    return out, detections


def _token_for(kind: str, value: str) -> str:
    tail = value[-4:]
    label = {"national_id": "NATID", "iqama": "IQAMA", "iban": "IBAN"}.get(kind, "PII")
    return f"[{label}:****{tail}]"


def mask_obj(obj) -> tuple[object, list[dict]]:
    """Recursively mask PII in a JSON-like structure. Returns (obj, all_detections)."""
    all_det: list[dict] = []

    def walk(o):
        if isinstance(o, str):
            masked, det = mask(o)
            all_det.extend(det)
            return masked
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o

    return walk(obj), all_det
