"""Unicode / RTL defense (spec §4.4.7, closes v7 flaw B13).

Arabic-first UIs carry heavy bidi text. Bidi-override chars, zero-width chars,
and homoglyphs let text render one way to a human approver and read another way
to the model. We normalize (NFKC), strip dangerous control chars, and flag when
anything was changed so the gateway can surface it. HITL previews always render
from the normalized form -- what the approver sees is what the model sees.
"""
import unicodedata

# Bidirectional formatting / override characters (Trojan Source class).
BIDI_CONTROLS = {
    "‪", "‫", "‬", "‭", "‮",  # LRE RLE PDF LRO RLO
    "⁦", "⁧", "⁨", "⁩",            # LRI RLI FSI PDI
    "‎", "‏",                                # LRM RLM
}
# Zero-width and other invisible characters.
ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿"}

DANGEROUS = BIDI_CONTROLS | ZERO_WIDTH


def sanitize(text: str) -> tuple[str, list[str]]:
    """Return (clean_text, flags). flags is non-empty when something was altered."""
    if not isinstance(text, str):
        return text, []
    flags: list[str] = []

    stripped_chars = [c for c in text if c in DANGEROUS]
    if stripped_chars:
        names = sorted({_char_name(c) for c in stripped_chars})
        flags.append("stripped_control_chars:" + ",".join(names))
    cleaned = "".join(c for c in text if c not in DANGEROUS)

    normalized = unicodedata.normalize("NFKC", cleaned)
    if normalized != cleaned:
        flags.append("nfkc_normalized")

    # Remaining C0/C1 control chars (except tab/newline/carriage-return).
    controls = [c for c in normalized if unicodedata.category(c) == "Cc" and c not in "\t\n\r"]
    if controls:
        flags.append("stripped_other_controls")
        normalized = "".join(c for c in normalized if c not in controls)

    # Homoglyph / confusable defense (Unicode TR39 mixed-script heuristic): a single
    # token mixing Latin with Cyrillic or Greek letters is the classic spoof
    # (e.g. "pаypal" with a Cyrillic а). We FLAG rather than rewrite — the approver
    # is warned and the taint layer treats it as suspicious. Arabic + Latin/digits
    # is legitimate in these UIs and is NOT flagged.
    confusable = _mixed_script_tokens(normalized)
    if confusable:
        flags.append("homoglyph_mixed_script:" + ",".join(confusable[:5]))

    return normalized, flags


# Confusable script families that should never co-occur inside one word token.
_CONFUSABLE_SCRIPTS = ("LATIN", "CYRILLIC", "GREEK")


def _token_scripts(token: str) -> set[str]:
    scripts = set()
    for c in token:
        if not c.isalpha():
            continue
        name = unicodedata.name(c, "")
        for s in _CONFUSABLE_SCRIPTS:
            if name.startswith(s):
                scripts.add(s)
                break
    return scripts


def _mixed_script_tokens(text: str) -> list[str]:
    """Tokens that mix two+ confusable scripts (Latin/Cyrillic/Greek)."""
    flagged = []
    for token in text.split():
        if len(_token_scripts(token) & set(_CONFUSABLE_SCRIPTS)) >= 2:
            flagged.append(token[:40])
    return flagged


def _char_name(c: str) -> str:
    try:
        return unicodedata.name(c)
    except ValueError:
        return f"U+{ord(c):04X}"


def sanitize_obj(obj):
    """Recursively sanitize all strings in a JSON-like structure. Returns (obj, all_flags)."""
    all_flags: list[str] = []

    def walk(o):
        if isinstance(o, str):
            clean, flags = sanitize(o)
            all_flags.extend(flags)
            return clean
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o

    return walk(obj), all_flags
