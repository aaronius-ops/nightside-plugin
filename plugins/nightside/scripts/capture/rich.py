"""The rich tier's summary (opt-in). OFF BY DEFAULT. Runs only when ALL of these hold:
  1. the config has "rich_summary": true (set by hand or `/planet privacy rich --summary`),
  2. the project's effective tier is "rich" (so it is public: a private project is always metadata),
  3. the user asked for it on this run (`/planet status --survey --rich`). It never runs inside a hook.

What the model sees: llm_input(), a subset of the deterministic manifest that has ALREADY passed the allow-list
(graph shape, agent roles/tiers/turns/minutes, the top tool counts, run and outcome counts) plus the project name
the user set. Never a transcript, a prompt, a tool input or output, a path, or anything not already approved to leave.

This is the plugin's only process that talks to a network service: it runs `claude -p` (Haiku, safe mode: no
CLAUDE.md, hooks, plugins, MCP servers or tools; no session saved), which sends llm_input() to Anthropic under the
user's own Claude Code login. The plugin itself opens no socket. The model's answer is untrusted: the summary must
pass the allow-list (<= 60 words, guard-clean) and the category must be in the enum, or it is dropped. A proposed
label must use only the closed label vocabulary (allowlist.check_label, source "claude") or it is dropped; a label
the user set always wins over it (surveyor.pick_label).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile

from capture import common as C
from capture import allowlist as A
from capture import labels as L

PROMPT = ("You describe the SHAPE of a software workflow for a public map, from counts only. Reply with one JSON "
          "object and nothing else: {\"summary\": \"<=50 plain words on what kind of workflow this is and how it "
          "is organised\", \"category\": \"<one of: %s>\", \"label\": \"<=40 characters, a short generic "
          "phrase for the map placard, e.g. Voice and audio pipeline\"}. Do not invent facts; no names of people, "
          "companies, places, products or money. Input:\n")
CLAUDE_ARGV = ["claude", "-p", "--safe-mode", "--model", "haiku", "--tools", "", "--no-session-persistence",
               "--output-format", "json"]


def opted_in(cfg: dict, manifest: dict) -> tuple[bool, str]:
    if cfg.get("rich_summary") is not True:
        return False, "rich summary is off (opt in: /planet privacy rich --summary)"
    if manifest.get("privacy_tier") != "rich":
        return False, "this project is at the metadata tier (private projects always are)"
    return True, "ok"


def llm_input(m: dict) -> dict:
    top = sorted(m["tools"].items(), key=lambda kv: (-kv[1], kv[0]))[:25]
    d = {"graph_shape": m["graph_shape"], "agents": m["agents"], "tools": dict(top),
         "runs": {"count": m["runs"]["count"], "total_minutes": m["runs"]["total_minutes"]},
         "outcomes": m["outcomes"]}
    if m.get("project_name"):
        d["project_name"] = m["project_name"]
    if m.get("label"):
        d["label"] = m["label"]  # the label already made on this machine (heuristic or the user's own)
    return d


def _claude(prompt: str, timeout: int = 120) -> str:
    env = dict(os.environ, NIGHTSIDE_CAPTURE="0", NIGHTSIDE_ARCHIVE="0")  # never capture the summarizer itself
    with tempfile.TemporaryDirectory() as d:  # no project CLAUDE.md, no repo context
        r = subprocess.run(CLAUDE_ARGV, input=prompt, capture_output=True, text=True, timeout=timeout, cwd=d, env=env)
    if r.returncode != 0:
        raise RuntimeError("claude -p failed")
    return r.stdout


def summarize(m: dict, runner=None) -> dict | None:
    """{"summary", "category"} that passed the allow-list, or None. `runner(prompt) -> stdout` (tests stub it)."""
    enum = [c for c in A.schema()["properties"]["category"]["enum"]]
    prompt = PROMPT % ", ".join(enum) + C.canonical(llm_input(m)).decode("ascii")
    try:
        raw = (runner or _claude)(prompt)
        try:
            raw = json.loads(raw).get("result", raw)
        except (ValueError, AttributeError):
            pass
        mo = re.search(r"\{.*\}", str(raw), re.S)
        ans = json.loads(mo.group(0)) if mo else {}
    except Exception:  # noqa: BLE001 - no summary is always a safe answer
        return None
    out = {}
    s = ans.get("summary") if isinstance(ans, dict) else None
    if isinstance(s, str):
        s = re.sub(r"\s+", " ", s).strip()
        trial = dict(m, summary=s)
        try:
            A.check_manifest(trial)
            out["summary"] = s
        except A.Rejected:
            pass
    c = ans.get("category") if isinstance(ans, dict) else None
    if c in enum and out:
        out["category"] = c
    lab = ans.get("label") if isinstance(ans, dict) else None
    if isinstance(lab, str) and out:  # model text: closed vocabulary only (allowlist.check_label, source claude)
        trial = {"text": L.normalise(lab), "category": out.get("category") or (m.get("label") or {}).get(
            "category", "unclassified"), "source": "claude"}
        if not A.check_label(trial, m.get("privacy_tier", "metadata")):
            out["label"] = trial
    return out or None
