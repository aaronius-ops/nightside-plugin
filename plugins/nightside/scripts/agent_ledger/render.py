"""Deterministic LEDGER.md tables from ledger.jsonl. Every number is computed from the file; nothing is typed.

The ledger-analyst agent writes the prose around these tables (scope, method, caveats); the tables themselves come
from here so they can be regenerated and diffed.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

from .ledger import read_ledger

VER = re.compile(r"\b(MERGE-WITH-FIXES|DEPLOY-WITH-FIXES|MERGE|BLOCK|DEPLOY|kept|sent_back)\b")
KINDS = ("build", "review", "fix", "design", "research", "ops", "other")


def short(m) -> str:
    return str(m or "unknown").replace("claude-", "")


def fmt(n) -> str:
    return f"{n:,}" if isinstance(n, int) else "-"


def cell(s) -> str:
    return str(s).replace("|", "/").replace("\n", " ")


def tables(rows: list[dict]) -> list[str]:
    runs = [r for r in rows if r.get("record") == "agent_run"]
    sess = [r for r in rows if r.get("record") == "session"]
    L = []
    w = L.append
    tok = [r["tokens"] for r in runs if isinstance(r.get("tokens"), int)]
    w("## Totals")
    w("")
    w(f"{len(runs)} agent runs in {len({r['session'] for r in runs})} sessions; tokens reported for {len(tok)} runs "
      f"({fmt(sum(tok))} in all); {sum(1 for r in runs if r.get('node') in (None, 'unmapped'))} runs unmapped.")
    w("")
    w("| | runs |")
    w("|---|---|")
    for k, v in sorted(Counter(r.get("status") for r in runs).items(), key=lambda x: (-x[1], str(x[0]))):
        w(f"| status {cell(k)} | {v} |")
    for k, v in sorted(Counter(r.get("launch") or "legacy" for r in runs).items(), key=lambda x: (-x[1], str(x[0]))):
        w(f"| launched via {cell(k)} | {v} |")
    w("")
    w("## Runs by kind and model")
    w("")
    models = sorted({short(r.get("model_used")) for r in runs})
    w("| Kind | " + " | ".join(models) + " | Total | Tokens |")
    w("|---|" + "---|" * (len(models) + 2))
    by_kind = defaultdict(list)
    for r in runs:
        by_kind[r.get("kind") or "other"].append(r)
    for k in sorted(by_kind, key=lambda k: (KINDS.index(k) if k in KINDS else 99, k)):
        rs = by_kind[k]
        c = Counter(short(r.get("model_used")) for r in rs)
        w(f"| {cell(k)} | " + " | ".join(str(c.get(m, 0)) for m in models) +
          f" | {len(rs)} | {fmt(sum(r['tokens'] for r in rs if isinstance(r.get('tokens'), int)))} |")
    w("")
    req = Counter((str(r.get("model_requested")), short(r.get("model_used"))) for r in runs)
    w("Requested vs used model: " + "; ".join(f"{a} -> {b}: {n}" for (a, b), n in sorted(req.items())) + ".")
    w("")
    w("## Runs by build-graph node")
    w("")
    w("| Node | Workstream | Runs | Build | Review | Fix | Other | Models used | Tokens | Verdicts |")
    w("|---|---|---|---|---|---|---|---|---|---|")
    by_node = defaultdict(list)
    for r in runs:
        by_node[r.get("node") or "unmapped"].append(r)
    for n in sorted(by_node, key=lambda n: (n == "unmapped", n)):
        rs = by_node[n]
        k = Counter(r.get("kind") for r in rs)
        ws = sorted({str(r["workstream"]) for r in rs if r.get("workstream")})
        ms = Counter(short(r.get("model_used")) for r in rs)
        vs = Counter(v for r in rs for v in VER.findall(r.get("verdict") or ""))
        oth = sum(v for kk, v in k.items() if kk not in ("build", "review", "fix"))
        w(f"| {cell(n)} | {cell(', '.join(ws)[:60]) or '-'} | {len(rs)} | {k['build']} | {k['review']} | {k['fix']} | "
          f"{oth} | {', '.join(f'{m} {c}' for m, c in sorted(ms.items()))} | "
          f"{fmt(sum(r['tokens'] for r in rs if isinstance(r.get('tokens'), int)))} | "
          f"{', '.join(f'{v} {c}' for v, c in sorted(vs.items())) or 'none'} |")
    w("")
    w("## Orchestrator models per session")
    w("")
    if sess:
        w("| Session | Project | Window (UTC) | Orchestrator models (assistant messages) | Agent runs |")
        w("|---|---|---|---|---|")
        for s in sorted(sess, key=lambda s: (s.get("first_ts") or "", s["key"])):
            segs = s.get("orchestrator_models") or []
            agg = Counter()
            for g in segs:
                agg[short(g.get("model"))] += g.get("messages") or 0
            seq = " -> ".join(dict.fromkeys(short(g.get("model")) for g in segs)) or "none"
            win = f"{(s.get('first_ts') or '')[:16].replace('T', ' ')} to {(s.get('last_ts') or '')[:16].replace('T', ' ')}"
            n_l = sum(1 for r in runs if r["session"] == s["session"])
            w(f"| {cell(s['session'][:8])} | {cell(s.get('project'))} | {win} | {seq} "
              f"({', '.join(f'{m} {n}' for m, n in sorted(agg.items()))}) | {n_l} |")
    else:
        w("No session rows in the ledger (rows from before schema_version 1 carry no orchestrator data).")
    w("")
    w("## Review verdicts")
    w("")
    rv = [r for r in runs if r.get("kind") == "review"]
    vc = Counter(v for r in rv for v in VER.findall(r.get("verdict") or ""))
    w(f"{len(rv)} review runs; {sum(1 for r in rv if r.get('verdict'))} returned a verdict word "
      f"({', '.join(f'{v} {c}' for v, c in sorted(vc.items())) or 'none'}); findings counted for "
      f"{sum(1 for r in rv if isinstance(r.get('findings_count'), int))} "
      f"({sum(r['findings_count'] for r in rv if isinstance(r.get('findings_count'), int))} findings in all).")
    w("")
    w("| Agent | Node | Description | Verdict | Findings | Basis |")
    w("|---|---|---|---|---|---|")
    for r in sorted(rv, key=lambda r: (r.get("launched_at") or "", r["key"])):
        w(f"| {cell(r['agent_id'][:10])} | {cell(r.get('node') or 'unmapped')} | {cell((r.get('description') or '')[:60])} "
          f"| {cell(r.get('verdict') or '-')} | {r.get('findings_count') if r.get('findings_count') is not None else '-'} "
          f"| {cell(r.get('findings_basis') or '-')} |")
    w("")
    return L


def main(ledger: Path, out: Path, title: str, preamble: Path | None = None) -> int:
    rows = read_ledger(ledger)
    L = [f"# {title}", "",
         f"Generated from `{ledger.name}` ({sum(1 for r in rows if r.get('record') == 'agent_run')} agent runs). "
         "Metadata only: no prompts, no report text. Regenerate with `agent_ledger render`; do not edit the tables "
         "by hand.", ""]
    if preamble and Path(preamble).is_file():  # the analyst's scope / method / caveats prose, kept in its own file
        L += Path(preamble).read_text(encoding="utf-8").rstrip().splitlines() + [""]
    L += tables(rows)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(L), encoding="utf-8")
    print(f"wrote {out} ({len(L)} lines)")
    return 0
