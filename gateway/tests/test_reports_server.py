"""Unit tests for servers/reports_server.py (Phase 2, task 7 — test debt).

The reports server is the only connector that WRITES a file, and it renders database
content into HTML that a human then opens in a browser. That makes two properties
load-bearing:

  * database values must be HTML-escaped — a product name containing markup would
    otherwise become stored XSS in a report an executive opens;
  * the report id must be validated against a fixed catalogue, so the output path can
    never be steered outside REPORTS_DIR.

Neither needs a live database: the rendering and validation paths are pure.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "servers"))
import reports_server as rs  # noqa: E402


def test_list_reports_returns_the_catalogue():
    out = json.loads(rs.list_reports())
    ids = {r["id"] for r in out["reports"]}
    assert "sales_overview" in ids
    assert all(r["description"] for r in out["reports"])


def test_unknown_report_is_refused_without_touching_the_database():
    """Validated against a fixed catalogue BEFORE any query or file write, so a caller
    cannot steer the output path."""
    out = json.loads(rs.generate_report("../../etc/passwd"))
    assert "error" in out and "unknown report" in out["error"]
    assert "available" in out


@pytest.mark.parametrize("evil", [
    "../../../etc/passwd",
    "sales_overview/../../secrets",
    "..\\..\\windows\\system32",
    "",
])
def test_report_id_cannot_escape_the_catalogue(evil):
    out = json.loads(rs.generate_report(evil))
    assert "error" in out, f"{evil!r} must not be accepted as a report id"


def test_database_values_are_html_escaped_in_the_rendered_report():
    """A product name is DATA. If it lands unescaped in the HTML, a poisoned row becomes
    script execution in whoever opens the report."""
    payload = "<script>alert('xss')</script>"
    rows = [{"name": payload, "category": "x", "revenue": 1, "units": 1}]

    bars = rs._bar_rows(rows, "name", "revenue", sub_key="category")
    assert payload not in bars
    assert "&lt;script&gt;" in bars

    trend = rs._trend(rows, "name", "revenue")
    assert payload not in trend
    assert "&lt;script&gt;" in trend

    kpi = rs._kpi(payload, "100", note=payload)
    assert payload not in kpi
    assert "&lt;script&gt;" in kpi


def test_full_render_escapes_hostile_rows_end_to_end():
    evil = '"><img src=x onerror=alert(1)>'
    data = {
        "kpis": {"revenue": 1000, "units": 5, "orders": 2, "aov": 500,
                 "products": 1, "regions": 1},
        "by_region": [{"region": evil, "revenue": 1000, "units": 5, "pct": 100}],
        "top_products": [{"name": evil, "category": evil, "revenue": 1000, "units": 5}],
        "monthly": [{"month": evil, "revenue": 1000}],
        "top_reps": [{"name": evil, "region": evil, "revenue": 1000}],
    }
    doc = rs._render_sales_overview(data, "2026-07-12 00:00 UTC")
    # What matters is that the payload cannot become an ELEMENT. The inner characters
    # ("onerror=alert(1)") may survive as visible text — that is inert. An unescaped
    # `<img` tag would not be.
    assert "<img" not in doc, "a hostile row produced a real <img> element"
    assert "&lt;img" in doc, "the payload should still be present, as escaped text"
    assert "<script" not in doc.replace("<script>", "")   # no injected script element
    assert doc.lstrip().lower().startswith("<!doctype") or "<html" in doc


def test_money_formatting_is_stable():
    assert rs._money(1234567) == "1,234,567"
    assert rs._money(0) == "0"
