"""A self-contained HTML page of spec.toml for a human to review and approve (D58).

The page shows the requirements, their invariants and the sha256 of the exact file, so an approval
names one version of the spec. With a run result laid over it, the same page is the gate's verdict
page gate.html (D65). It is a view only: the gate and the checker do not read it.
"""

import hashlib
import json
from html import escape
from pathlib import Path

from witnessbox.checker.input import load_spec
from witnessbox.checker.rendering import _short

# Findings shown per invariant on the verdict page; the rest are in report.md.
MAX_FINDINGS = 5
LIMITS = ("The gate does not see decisions without ev() or outcomes without an observation scenario; "
          "see docs/security.md.")

CSS = """
/* Layout: one reading column; each requirement is a section, its invariants are bordered panels inside it. */
:root {
  --paper: #f6f7f9;
  --surface: #ffffff;
  --ink: #18202b;
  --muted: #5b6676;
  --rule: #d9dee6;
  --accent: #1f4fb8;
  --accent-soft: #e7eefc;
  --warn: #8a5300;
  --warn-soft: #fbf0dc;
  --font-body: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --font-mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --paper: #11161d; --surface: #18202a; --ink: #e4e9f0; --muted: #98a3b3;
    --rule: #2b3542; --accent: #8fb0ff; --accent-soft: #1e2b45;
    --warn: #f0b860; --warn-soft: #3a2c14;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --paper: #11161d; --surface: #18202a; --ink: #e4e9f0; --muted: #98a3b3;
  --rule: #2b3542; --accent: #8fb0ff; --accent-soft: #1e2b45;
  --warn: #f0b860; --warn-soft: #3a2c14;
}
body {
  margin: 0; background: var(--paper); color: var(--ink);
  font: 15px/1.6 var(--font-body);
  padding-left: max(16px, env(safe-area-inset-left, 0px));
  padding-right: max(16px, env(safe-area-inset-right, 0px));
}
.page { max-width: 860px; margin: 0 auto; padding-block: 40px 64px; display: grid; gap: 40px; }
h1, h2, h3 { text-wrap: balance; margin: 0; line-height: 1.2; font-weight: 650; }
h1 { font-size: 32px; letter-spacing: -0.01em; }
h2 { font-size: 21px; }
h3 { font-size: 16px; }
code, .mono { font-family: var(--font-mono); font-size: 0.92em; }
.label { font-size: 11px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); }

header { display: grid; gap: 20px; }
.file { color: var(--muted); font-family: var(--font-mono); font-size: 13px; overflow-wrap: anywhere; }
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1px;
  background: var(--rule); border: 1px solid var(--rule); border-radius: 6px; overflow: hidden; }
.fact { background: var(--surface); padding: 12px 14px; display: grid; gap: 2px; }
.fact .value { font-family: var(--font-mono); font-size: 15px; font-variant-numeric: tabular-nums; }
.hash { display: grid; gap: 4px; padding: 12px 14px; border: 1px dashed var(--accent);
  border-radius: 6px; background: var(--accent-soft); }
.hash .value { font-family: var(--font-mono); font-size: 13px; overflow-wrap: anywhere; }
.hash .value b { color: var(--accent); font-weight: 650; }

nav ol { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 8px; }
nav a { display: inline-block; padding: 4px 10px; border: 1px solid var(--rule); border-radius: 4px;
  color: var(--ink); text-decoration: none; font-family: var(--font-mono); font-size: 13px; background: var(--surface); }
nav a:hover, nav a:focus-visible { border-color: var(--accent); color: var(--accent); }
a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

.req { display: grid; gap: 16px; padding-top: 24px; border-top: 2px solid var(--ink); scroll-margin-top: 16px; }
.req-head, .inv-head { display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between; gap: 6px 16px; }
.req-text, .statement { margin: 0; max-width: 65ch; }
.source { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; font-size: 14px; color: var(--muted); }
.flag { display: inline-block; padding: 1px 8px; border-radius: 3px; font-size: 12px; font-weight: 600;
  color: var(--warn); background: var(--warn-soft); }

.inv { background: var(--surface); border: 1px solid var(--rule); border-radius: 6px; padding: 16px 18px;
  display: grid; gap: 14px; scroll-margin-top: 16px; }
.rows { display: grid; grid-template-columns: max-content 1fr; gap: 10px 16px; align-items: baseline; margin: 0; }
.rows dt, .rows dd { margin: 0; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; list-style: none; margin: 0; padding: 0; }
.chips li { font-family: var(--font-mono); font-size: 13px; padding: 1px 8px; border-radius: 3px;
  border: 1px solid var(--rule); background: var(--paper); }
.chips.witness li { border-color: var(--accent); color: var(--accent); background: var(--accent-soft); }
.note { font-size: 13px; color: var(--muted); }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; font-family: var(--font-mono); font-size: 13px; }
th, td { text-align: left; padding: 4px 16px 4px 0; border-bottom: 1px solid var(--rule); }
th { font-family: var(--font-body); font-size: 11px; font-weight: 600; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--muted); }
td.arrow { color: var(--muted); padding-right: 8px; }

footer { font-size: 13px; color: var(--muted); border-top: 1px solid var(--rule); padding-top: 16px; }

@media (max-width: 520px) {
  h1 { font-size: 26px; }
  .rows { grid-template-columns: 1fr; gap: 4px; }
  .rows dd { margin-bottom: 8px; }
}
"""

# Only the verdict page uses these rules, so the spec page stays byte-for-byte the same.
RUN_CSS = """
.verdict { display: grid; gap: 6px; padding: 12px 14px; border-radius: 6px; border: 1px solid var(--warn);
  background: var(--warn-soft); }
.verdict.pass { border-color: var(--accent); background: var(--accent-soft); }
.verdict .value { font-family: var(--font-mono); font-size: 20px; font-weight: 650; }
.verdict a { color: inherit; }
.status { display: inline-block; padding: 1px 8px; border-radius: 3px; font-size: 12px; font-weight: 600;
  color: var(--warn); background: var(--warn-soft); }
.status.confirmed { color: var(--accent); background: var(--accent-soft); }
.items { margin: 0; padding-left: 18px; display: grid; gap: 4px; font-size: 14px; }
.items code { overflow-wrap: anywhere; }
.run-section { display: grid; gap: 12px; padding-top: 24px; border-top: 2px solid var(--ink); }
"""


def _chips(items: list[str], cls: str = "") -> str:
    return f'<ul class="chips {cls}">' + "".join(f"<li>{escape(i)}</li>" for i in items) + "</ul>"


def _flag(text: str) -> str:
    return f'<span class="flag">{escape(text)}</span>'


def _inv_status(inv_id: str, report: dict) -> str:
    """The first that applies: a finding, out of scope, never fired, uncovered partitions, confirmed."""
    if any(f.get("inv") == inv_id for f in report.get("findings", [])):
        return "finding"
    scope = report.get("coverage_scope")
    if scope is not None and inv_id not in scope:
        return "out of scope"
    if inv_id in report.get("inv_never_fired", []):
        return "never fired"
    if inv_id in report.get("uncovered_partitions", {}):
        return "uncovered"
    return "confirmed"


def _items(items: list[str]) -> str:
    return f'<ul class="items">{"".join(f"<li>{i}</li>" for i in items)}</ul>'


def _finding(f: dict) -> str:
    where = f"line {f.get('line')}" if f.get("line") else "log"
    return f'<code>{escape(str(f.get("kind")))}</code> {escape(where)}: {escape(str(f.get("reason", "")))}'


def _run_rows(inv_id: str, report: dict) -> list[tuple[str, str]]:
    status = _inv_status(inv_id, report)
    rows = [("Status", f'<span class="status {status.replace(" ", "-")}">{escape(status)}</span>')]
    findings = [f for f in report.get("findings", []) if f.get("inv") == inv_id]
    if findings:
        shown = [_finding(f) for f in findings[:MAX_FINDINGS]]
        if len(findings) > MAX_FINDINGS:
            shown.append(f"and {len(findings) - MAX_FINDINGS} more in report.md")
        rows.append(("Findings", _items(shown)))
    if status in ("out of scope", "never fired"):
        return rows
    examples = report.get("partition_examples", {}).get(inv_id, {})
    parts = [f'<code>{escape(part)}</code> <span class="note">line {escape(str(ex.get("line")))}</span> '
             f'<code>{escape(_short(ex.get("data")))}</code>' for part, ex in examples.items()]
    parts += [f'<code>{escape(part)}</code> {_flag("not covered")}'
              for part in report.get("uncovered_partitions", {}).get(inv_id, [])]
    if parts:
        rows.append(("In this run", _items(parts)))
    return rows


def _no_obs(inv_ids: list[str]) -> bool:
    return bool(inv_ids) and not any(i.endswith("-OBS") for i in inv_ids)


def _run_sections(spec: dict, by_req: dict[str, list[str]], report: dict) -> str:
    outside = [_finding(f) + f' · <code>{escape(str(f.get("inv") or "—"))}</code>'
               for f in report.get("findings", []) if f.get("inv") not in spec["inv"]]
    scope = report.get("coverage_scope")
    out_of_scope = [] if scope is None else [i for i in spec["inv"] if i not in scope]
    no_obs = [r for r, ids in by_req.items() if _no_obs(ids)]
    known = [f'<code>{escape(str(f.get("inv")))}</code> ' + _finding(f) for f in report.get("known_findings", [])]

    def listed(title: str, items: list[str]) -> str:
        return f'<h3>{escape(title)}</h3>' + (_items(items) if items else '<p class="note">none</p>')

    sections = []
    if outside:
        sections.append('<section class="run-section" id="outside-spec"><h2>Findings outside the spec</h2>'
                        '<p class="note">Records whose invariant is not in spec.toml or that are not tied to one.</p>'
                        f"{_items(outside)}</section>")
    sections.append(
        '<section class="run-section" id="not-verified"><h2>Not verified</h2>'
        '<p class="note">This list does not change the verdict.</p>'
        + listed("Requirements without -OBS", [f"<code>{escape(r)}</code>" for r in no_obs])
        + listed("Invariants out of scope", [f"<code>{escape(i)}</code>" for i in out_of_scope])
        + listed("Findings forgiven by known.toml", known)
        + f'<p>{escape(LIMITS)}</p></section>')
    return "".join(sections)


def _invariant(inv_id: str, inv: dict, report: dict | None = None) -> str:
    rows = [("Checker", f'<code>{escape(inv["checker"])}</code>'),
            ("Witness", _chips(inv["witness"], "witness"))]
    if inv.get("transitions"):
        body = "".join(f'<tr><td>{escape(a)}</td><td>{escape(e)}</td><td class="arrow">→</td><td>{escape(b)}</td></tr>'
                       for a, e, b in inv["transitions"])
        rows.append(("Transitions",
                     '<div class="table-wrap"><table><thead><tr><th>From</th><th>Event</th><th></th><th>To</th>'
                     f'</tr></thead><tbody>{body}</tbody></table></div>'
                     f'<p class="note">One coverage partition per transition: {len(inv["transitions"])}.</p>'))
    elif inv.get("partitions"):
        rows.append(("Partitions", _chips(inv["partitions"])))
    else:
        rows.append(("Partitions", _flag("none")))
    if inv.get("not_in_verdict"):
        rows.append(("Not in verdict", _chips(inv["not_in_verdict"])))
    if report is not None:
        rows.extend(_run_rows(inv_id, report))
    statement = inv.get("statement")
    statement_html = f'<p class="statement">{escape(statement)}</p>' if statement else f"<p>{_flag('no statement')}</p>"
    rows_html = "".join(f'<dt class="label">{k}</dt><dd>{v}</dd>' for k, v in rows)
    return (f'<article class="inv" id="{escape(inv_id)}"><div class="inv-head">'
            f'<h3 class="mono">{escape(inv_id)}</h3><span class="label">Invariant</span></div>'
            f'{statement_html}<dl class="rows">{rows_html}</dl></article>')


def render(spec: dict, raw: bytes, shown_path: str, run: dict | None = None) -> str:
    """The page for a spec already validated by load_spec; raw is the file bytes the hash is taken from.
    run = {"report": parsed report.json, "result": "PASS" | "FAIL" | "ERROR", "reasons": [...]} lays
    the run result over the spec: the gate's verdict page (D65). Without run the page is unchanged."""
    report = run["report"] if run is not None else None
    sha = hashlib.sha256(raw).hexdigest()
    reqs, invs = spec["req"], spec["inv"]
    by_req: dict[str, list[str]] = {req_id: [] for req_id in reqs}
    for inv_id, inv in invs.items():
        by_req[inv["req"]].append(inv_id)
    uncovered = sum(1 for ids in by_req.values() if not ids)
    no_source = sum(1 for req in reqs.values() if not req.get("source"))
    facts = [("Version", spec["meta"].get("version", "—")), ("Requirements", len(reqs)),
             ("Invariants", len(invs)), ("Without invariants", uncovered), ("Without source", no_source)]
    facts_html = "".join(f'<div class="fact"><span class="label">{k}</span>'
                         f'<span class="value">{escape(str(v))}</span></div>' for k, v in facts)
    nav = "".join(f'<li><a href="#{escape(r)}">{escape(r)}</a></li>' for r in reqs)

    sections = []
    for req_id, req in reqs.items():
        source = req.get("source")
        source_html = escape(" ".join(str(source).split())) if source else _flag("not given")
        invariants = "".join(_invariant(i, invs[i], report) for i in by_req[req_id]) or (
            f'<p>{_flag("no invariants")} <span class="note">The gate does not check this requirement.</span></p>')
        sections.append(
            f'<section class="req" id="{escape(req_id)}"><div class="req-head">'
            f'<h2 class="mono">{escape(req_id)}</h2><span class="label">Requirement</span></div>'
            f'<p class="req-text">{escape(" ".join(str(req.get("text", "")).split()))}</p>'
            f'<div class="source"><span class="label">Source</span><span>{source_html}</span></div>'
            + (f"<p>{_flag('no -OBS')} <span class=\"note\">Only the decision level checks this requirement.</span></p>"
               if report is not None and _no_obs(by_req[req_id]) else "")
            + f"{invariants}</section>")

    path = Path(shown_path)
    project = path.parent.parent.name if path.parent.name == "ebt" else path.parent.name
    kind = "EBT verdict" if run is not None else "EBT spec"
    title = f"{project} {kind}" if project else kind
    verdict_html, run_html, css = "", "", CSS
    if run is not None:
        result = str(run["result"])
        reasons = ", ".join(run["reasons"]) or "none"
        verdict_html = (f'<div class="verdict{" pass" if result == "PASS" else ""}"><span class="label">Gate result</span>'
                        f'<span class="value">{escape(result)}</span><span>Reasons: {escape(reasons)}</span>'
                        '<span><a href="gate.md">gate.md</a> · <a href="report.md">report.md</a> · '
                        '<a href="spec.html">spec.html</a></span></div>')
        run_html = _run_sections(spec, by_req, report)
        css = CSS + RUN_CSS
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="claude:viewport-fit-sides" content="cover">
<title>{escape(title)}</title>
<style>{css}</style>
</head>
<body>
<div class="page">
<header>
  <div class="file">{escape(shown_path)}</div>
  <h1>{escape(title)}</h1>
  {verdict_html}<div class="facts">{facts_html}</div>
  <div class="hash"><span class="label">spec.toml sha256 · an approval names exactly this file</span>
    <span class="value"><b>{sha[:12]}</b>{sha[12:]}</span></div>
  <nav aria-label="Requirements"><ol>{nav}</ol></nav>
</header>
{"".join(sections)}{run_html}
<footer>Built from {escape(shown_path)}. The gate and the checker report print the first 12 characters
of this hash. Any edit of the file changes the hash, and the spec has to be approved again.</footer>
</div>
</body>
</html>
"""


def write_gate_page(spec_path, report_path, out_path, shown_path, result: str, reasons: str) -> None:
    """The verdict page gate.html (D65): the checked spec with report.json laid over it.
    reasons is the gate's comma-separated list. Raises on a bad spec or report; then out_path is not written."""
    spec_path, out_path = Path(spec_path), Path(out_path)
    spec, _ = load_spec(spec_path)
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("report.json is not a JSON object")
    run = {"report": report, "result": result, "reasons": [r for r in reasons.split(",") if r]}
    html = render(spec, spec_path.read_bytes(), str(shown_path), run)
    tmp = out_path.with_name(out_path.name + ".tmp")
    tmp.write_text(html, encoding="utf-8")
    tmp.replace(out_path)


def write_page(spec_path, out_path, shown_path=None) -> str:
    """Validates spec_path as the checker does, writes the page to out_path, returns the full sha256."""
    spec_path, out_path = Path(spec_path), Path(out_path)
    spec, _ = load_spec(spec_path)
    raw = spec_path.read_bytes()
    out_path.write_text(render(spec, raw, str(shown_path or spec_path)), encoding="utf-8")
    return hashlib.sha256(raw).hexdigest()
