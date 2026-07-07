"""reports-mcp — generates polished, self-contained HTML business reports from the
database. A demo of the gateway as more than a data pipe: the AI asks for a report,
the tool runs curated read-only queries and returns a stakeholder-ready dashboard.

Read-only: every query runs in a READ ONLY transaction. Configuration via env
(never model-visible args): POSTGRES_URL / DATABASE_URL, REPORTS_DIR (output).
Runs over stdio; the gateway spawns it.
"""
from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reports")

CONNINFO = os.environ.get("POSTGRES_URL") or os.environ.get("DATABASE_URL") or ""
REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "data/reports"))
_STMT_TIMEOUT_MS = 15000

# --- design tokens (single accent + considered slate neutrals; light & dark) ----
_ACCENT = "#0e7c86"          # deep teal — the one accent, used for magnitude
_ACCENT_SOFT = "#7bc6cc"

REPORTS = {
    "sales_overview": "Sales Overview — company-wide revenue, regions, products, trend",
}


def _conn():
    if not CONNINFO:
        raise RuntimeError("reports-mcp not configured: set POSTGRES_URL")
    c = psycopg.connect(CONNINFO, connect_timeout=8, row_factory=dict_row)
    with c.cursor() as cur:
        cur.execute(f"SET statement_timeout = {_STMT_TIMEOUT_MS}")
        cur.execute("SET default_transaction_read_only = on")
    return c


def _q(cur, sql):
    cur.execute(sql)
    return cur.fetchall()


def _money(v) -> str:
    return f"{float(v):,.0f}"


def _bar_rows(items, label_key, value_key, sub_key=None):
    """Horizontal magnitude bars: 4px rounded ends, baseline-anchored, direct labels."""
    if not items:
        return "<p class='empty'>No data.</p>"
    top = max(float(i[value_key]) for i in items) or 1.0
    out = []
    for i in items:
        val = float(i[value_key])
        pct = max(2.0, val / top * 100)
        sub = f"<span class='sub'>{html.escape(str(i[sub_key]))}</span>" if sub_key else ""
        out.append(
            f"<div class='bar-row'>"
            f"<div class='bar-label'>{html.escape(str(i[label_key]))}{sub}</div>"
            f"<div class='bar-track'><div class='bar-fill' style='width:{pct:.1f}%'></div></div>"
            f"<div class='bar-val'>{_money(val)}</div></div>")
    return "\n".join(out)


def _trend(items, label_key, value_key):
    """Vertical bars for the monthly trend — 2px surface gap, emphasized last month."""
    if not items:
        return "<p class='empty'>No data.</p>"
    top = max(float(i[value_key]) for i in items) or 1.0
    cols = []
    for idx, i in enumerate(items):
        val = float(i[value_key])
        h = max(3.0, val / top * 100)
        last = " last" if idx == len(items) - 1 else ""
        cols.append(
            f"<div class='tcol'><div class='tbar-wrap'>"
            f"<div class='tval'>{_money(val/1000)}k</div>"
            f"<div class='tbar{last}' style='height:{h:.1f}%'></div></div>"
            f"<div class='tlabel'>{html.escape(str(i[label_key]))}</div></div>")
    return "\n".join(cols)


def _kpi(label, value, note=""):
    note = f"<div class='kpi-note'>{html.escape(note)}</div>" if note else ""
    return (f"<div class='kpi'><div class='kpi-label'>{html.escape(label)}</div>"
            f"<div class='kpi-val'>{value}</div>{note}</div>")


def _render_sales_overview(data: dict, generated: str) -> str:
    k = data["kpis"]
    regions_tbl = "\n".join(
        f"<tr><td>{html.escape(r['region'])}</td>"
        f"<td class='num'>{_money(r['revenue'])}</td>"
        f"<td class='num'>{int(r['units']):,}</td>"
        f"<td class='num'>{float(r['pct']):.1f}%</td></tr>"
        for r in data["by_region"])
    products_tbl = "\n".join(
        f"<tr><td>{html.escape(p['name'])}</td><td>{html.escape(p['category'])}</td>"
        f"<td class='num'>{_money(p['revenue'])}</td>"
        f"<td class='num'>{int(p['units']):,}</td></tr>"
        for p in data["top_products"])
    reps_tbl = "\n".join(
        f"<tr><td>{html.escape(r['name'])}</td><td>{html.escape(r['region'])}</td>"
        f"<td class='num'>{_money(r['revenue'])}</td></tr>"
        for r in data["top_reps"])

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sales Overview — Najd Retail</title>
<style>
  :root {{
    --bg:#f4f6f8; --card:#ffffff; --ink:#141b22; --muted:#5c6773; --line:#e2e7ec;
    --accent:{_ACCENT}; --accent-soft:{_ACCENT_SOFT}; --track:#eef1f4; color-scheme:light dark;
  }}
  @media (prefers-color-scheme:dark) {{
    :root {{ --bg:#0f151b; --card:#182029; --ink:#e9edf1; --muted:#93a1ad;
      --line:#26303a; --track:#212b35; }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font-family:"Segoe UI",system-ui,-apple-system,sans-serif; line-height:1.5; }}
  .wrap {{ max-width:1080px; margin:0 auto; padding:36px 24px 64px; }}
  .head {{ display:flex; justify-content:space-between; align-items:flex-end;
    flex-wrap:wrap; gap:12px; border-bottom:2px solid var(--accent); padding-bottom:16px; }}
  .eyebrow {{ font-size:12px; font-weight:700; letter-spacing:.14em; text-transform:uppercase;
    color:var(--accent); margin:0 0 4px; }}
  h1 {{ font-size:27px; margin:0; }}
  .gen {{ font-size:12.5px; color:var(--muted); text-align:right; }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
    gap:14px; margin:24px 0; }}
  .kpi {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px 18px; }}
  .kpi-label {{ font-size:12px; color:var(--muted); font-weight:600; text-transform:uppercase; letter-spacing:.05em; }}
  .kpi-val {{ font-size:26px; font-weight:700; margin-top:4px; font-variant-numeric:tabular-nums; }}
  .kpi-note {{ font-size:12px; color:var(--muted); margin-top:2px; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
  @media (max-width:760px) {{ .grid {{ grid-template-columns:1fr; }} }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:14px; padding:20px 22px; }}
  .card h2 {{ font-size:15px; margin:0 0 16px; letter-spacing:.01em; }}
  .card.full {{ grid-column:1 / -1; }}
  /* horizontal bars */
  .bar-row {{ display:grid; grid-template-columns:150px 1fr 92px; align-items:center;
    gap:12px; margin:9px 0; }}
  .bar-label {{ font-size:13px; }} .bar-label .sub {{ color:var(--muted); font-size:11.5px; margin-left:6px; }}
  .bar-track {{ background:var(--track); border-radius:5px; height:14px; overflow:hidden; }}
  .bar-fill {{ height:100%; background:var(--accent); border-radius:5px; }}
  .bar-val {{ text-align:right; font-size:13px; font-variant-numeric:tabular-nums; color:var(--muted); }}
  /* vertical trend */
  .trend {{ display:flex; gap:8px; align-items:flex-end; height:200px; padding-top:18px; }}
  .tcol {{ flex:1; display:flex; flex-direction:column; align-items:center; height:100%; }}
  .tbar-wrap {{ flex:1; width:100%; display:flex; flex-direction:column; justify-content:flex-end;
    align-items:center; position:relative; }}
  .tbar {{ width:70%; background:var(--accent-soft); border-radius:4px 4px 0 0; }}
  .tbar.last {{ background:var(--accent); }}
  .tval {{ font-size:10.5px; color:var(--muted); margin-bottom:4px; font-variant-numeric:tabular-nums; }}
  .tlabel {{ font-size:11px; color:var(--muted); margin-top:6px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ text-align:left; padding:8px 6px; border-bottom:1px solid var(--line); }}
  th {{ font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); font-weight:600; }}
  td.num, th.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  tr:last-child td {{ border-bottom:0; }}
  .foot {{ margin-top:26px; font-size:11.5px; color:var(--muted); text-align:center;
    border-top:1px solid var(--line); padding-top:16px; }}
  .empty {{ color:var(--muted); font-size:13px; }}
</style></head><body><div class="wrap">
  <div class="head">
    <div><p class="eyebrow">Najd Retail · Confidential</p><h1>Sales Overview</h1></div>
    <div class="gen">Generated {html.escape(generated)}<br>H1 2026 · Jan–Jun</div>
  </div>

  <div class="kpis">
    {_kpi("Total Revenue", _money(k['revenue']) + " <span style='font-size:14px'>SAR</span>")}
    {_kpi("Units Sold", f"{int(k['units']):,}")}
    {_kpi("Orders", f"{int(k['orders']):,}")}
    {_kpi("Avg Order Value", _money(k['aov']) + " <span style='font-size:14px'>SAR</span>")}
    {_kpi("Active Products", str(k['products']))}
    {_kpi("Regions", str(k['regions']))}
  </div>

  <div class="grid">
    <div class="card">
      <h2>Revenue by Region</h2>
      {_bar_rows(data['by_region'], 'region', 'revenue')}
    </div>
    <div class="card">
      <h2>Top Products by Revenue</h2>
      {_bar_rows(data['top_products'], 'name', 'revenue', sub_key='category')}
    </div>
    <div class="card full">
      <h2>Monthly Revenue Trend</h2>
      <div class="trend">{_trend(data['monthly'], 'month', 'revenue')}</div>
    </div>
    <div class="card">
      <h2>Region Detail</h2>
      <table><thead><tr><th>Region</th><th class="num">Revenue</th>
        <th class="num">Units</th><th class="num">Share</th></tr></thead>
        <tbody>{regions_tbl}</tbody></table>
    </div>
    <div class="card">
      <h2>Top Sales Representatives</h2>
      <table><thead><tr><th>Name</th><th>Region</th><th class="num">Revenue</th></tr></thead>
        <tbody>{reps_tbl}</tbody></table>
    </div>
    <div class="card full">
      <h2>Product Detail</h2>
      <table><thead><tr><th>Product</th><th>Category</th>
        <th class="num">Revenue</th><th class="num">Units</th></tr></thead>
        <tbody>{products_tbl}</tbody></table>
    </div>
  </div>

  <div class="foot">Generated by the Secure MCP Gateway · reports-mcp · read-only ·
    every query authorized, classified and audited. Figures are illustrative demo data.</div>
</div></body></html>"""


@mcp.tool()
def list_reports() -> str:
    """List the report types this server can generate."""
    return json.dumps({"reports": [{"id": k, "description": v} for k, v in REPORTS.items()]},
                      ensure_ascii=False)


@mcp.tool()
def generate_report(report: str = "sales_overview") -> str:
    """Generate a polished, self-contained HTML business report and save it. Returns
    the headline figures, a short summary, and the saved file path. `report` is one
    of the ids from list_reports (default: sales_overview)."""
    if report not in REPORTS:
        return json.dumps({"error": f"unknown report '{report}'",
                           "available": list(REPORTS)}, ensure_ascii=False)
    try:
        with _conn() as c, c.cursor() as cur:
            kpi = _q(cur, """
                SELECT round(sum(revenue)) AS revenue, sum(units) AS units,
                       count(*) AS orders, round(avg(revenue)) AS aov
                FROM demo.sales""")[0]
            prod_reg = _q(cur, """
                SELECT count(DISTINCT product_id) AS products,
                       count(DISTINCT region_id) AS regions FROM demo.sales""")[0]
            total = float(kpi["revenue"]) or 1.0
            by_region = _q(cur, """
                SELECT r.name AS region, round(sum(s.revenue)) AS revenue,
                       sum(s.units) AS units,
                       round(sum(s.revenue)*100.0/(SELECT sum(revenue) FROM demo.sales),1) AS pct
                FROM demo.sales s JOIN demo.regions r ON r.id=s.region_id
                GROUP BY r.name ORDER BY revenue DESC""")
            top_products = _q(cur, """
                SELECT p.name, p.category, round(sum(s.revenue)) AS revenue, sum(s.units) AS units
                FROM demo.sales s JOIN demo.products p ON p.id=s.product_id
                GROUP BY p.name, p.category ORDER BY revenue DESC LIMIT 6""")
            monthly = _q(cur, """
                SELECT to_char(date_trunc('month', sale_date),'Mon') AS month,
                       round(sum(revenue)) AS revenue
                FROM demo.sales GROUP BY date_trunc('month', sale_date)
                ORDER BY date_trunc('month', sale_date)""")
            top_reps = _q(cur, """
                SELECT rp.name, r.name AS region, round(sum(s.revenue)) AS revenue
                FROM demo.sales s JOIN demo.reps rp ON rp.id=s.rep_id
                JOIN demo.regions r ON r.id=rp.region_id
                GROUP BY rp.name, r.name ORDER BY revenue DESC LIMIT 5""")
    except Exception as e:
        return json.dumps({"error": f"report query failed: {e}"}, ensure_ascii=False)

    data = {"kpis": {**kpi, **prod_reg}, "by_region": by_region,
            "top_products": top_products, "monthly": monthly, "top_reps": top_reps}
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc = _render_sales_overview(data, generated)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORTS_DIR / f"{report}.html"
    out.write_text(doc, encoding="utf-8")

    return json.dumps({
        "report": report,
        "title": "Sales Overview — Najd Retail (H1 2026)",
        "saved_to": str(out),
        "html_bytes": len(doc.encode("utf-8")),
        "headline": {
            "total_revenue_sar": float(kpi["revenue"]),
            "units": int(kpi["units"]),
            "orders": int(kpi["orders"]),
            "avg_order_value_sar": float(kpi["aov"]),
            "top_region": by_region[0]["region"] if by_region else None,
            "top_product": top_products[0]["name"] if top_products else None,
        },
        "summary": (f"H1 2026: {_money(kpi['revenue'])} SAR across {int(kpi['orders'])} orders. "
                    f"Top region {by_region[0]['region']} ({_money(by_region[0]['revenue'])} SAR); "
                    f"top product {top_products[0]['name']}."),
    }, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run()  # stdio
