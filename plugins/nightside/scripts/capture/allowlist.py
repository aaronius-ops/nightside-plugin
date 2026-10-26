"""The fail-closed allow-list every outgoing document passes . Two layers:

1. schema: the WorkflowManifest JSON Schema (workflow_manifest.schema.json, a byte copy of
   the server's schema), checked with a small stdlib validator.
2. allow-list: every string leaf must match the pattern for its exact key path and the privacy tier; numbers must be
   finite and >= 0; nothing else may appear. Free text exists only in the rich tier (project_name, summary) and must
   pass the ledger guard unchanged. The optional `label` (check_label) is the one short text allowed at the metadata
   tier, and there only in generic VOCAB words. Optional `canaries` (the auditor's planted secrets) must not occur in the bytes.

check_envelope() is the gate: the surveyor calls it before writing the outbox, the preview before showing bytes, and
the confirmed upload calls it again on the exact bytes it sends. Any failure raises Rejected.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
from pathlib import Path

from capture import common as C  # noqa: F401  (puts scripts/ on the path for agent_ledger)
from agent_ledger.guard import Guard
from capture import labels as L

SCHEMA_PATH = Path(__file__).resolve().parent / "workflow_manifest.schema.json"
ENVELOPE_SCHEMA = "nightside/upload-envelope/0-draft"   # unsigned (v0): still accepted, never publishable
ENVELOPE_SCHEMA_SIGNED = "nightside/upload-envelope/1"   # v1: + "attestation" (plugin-signed run evidence)
ENVELOPE_KEYS = {"schema", "visibility", "manifest"}
ATTEST_KEYS = {"v", "key", "runs", "sig"}
ATTEST_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,15}\.[A-Za-z0-9_-]{22}$")   # <keyring kid>.<upload token id>
ATTEST_SIG_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")                            # base64url HMAC-SHA256
RUN_ID_RE = re.compile(r"^[0-9a-f]{16}$")                                     # random per run (hook.py), never derived
MAX_RUNS = 4096

BUILTIN_ROLES = {"orchestrator", "agent", "other", "general-purpose", "Explore", "Plan", "claude-code-guide",
                 "statusline-setup", "fork"}
# names are encoded by the hook at write time (hook.encode_tool / encode_agent): the same rules hold at both tiers,
# except that the rich tier keeps an MCP tool's own name after the hashed server
ROLE_META = re.compile(r"^custom-[0-9a-f]{6}$")
TOOL_RICH = re.compile(r"^(?:[A-Z][A-Za-z]{1,39}|mcp__[0-9a-f]{8}__[A-Za-z0-9][A-Za-z0-9_-]{0,63}|other)$")
TOOL_META = re.compile(r"^(?:[A-Z][A-Za-z]{1,39}|mcp-[0-9a-f]{8}|other)$")
SRV_META = re.compile(r"^srv-[0-9a-f]{8}$")
NAME_RICH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,59}$")
MINUTE_TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:00Z$")
LONG_TOKEN = re.compile(r"[A-Za-z0-9]{32,}")

_GUARD = None


class Rejected(ValueError):
    pass


def guard() -> Guard:
    global _GUARD
    if _GUARD is None:
        _GUARD = Guard()
    return _GUARD


def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------------------ schema subset ---
def validate_schema(v, s: dict, where: str = "$") -> list[str]:
    errs: list[str] = []
    t = s.get("type")
    if "enum" in s and v not in s["enum"]:
        errs.append(f"{where}: {v!r} not in enum")
    if t == "object":
        if not isinstance(v, dict):
            return errs + [f"{where}: not an object"]
        for k in s.get("required", []):
            if k not in v:
                errs.append(f"{where}: missing {k}")
        props = s.get("properties", {})
        ap = s.get("additionalProperties", True)
        for k, x in v.items():
            if k in props:
                errs += validate_schema(x, props[k], f"{where}.{k}")
            elif ap is False:
                errs.append(f"{where}: unexpected key {k!r}")
            elif isinstance(ap, dict):
                errs += validate_schema(x, ap, f"{where}.{k}")
    elif t == "array":
        if not isinstance(v, list):
            return errs + [f"{where}: not an array"]
        if "maxItems" in s and len(v) > s["maxItems"]:
            errs.append(f"{where}: too many items")
        for i, x in enumerate(v):
            errs += validate_schema(x, s.get("items", {}), f"{where}[{i}]")
    elif t == "string":
        if not isinstance(v, str):
            return errs + [f"{where}: not a string"]
        if "maxLength" in s and len(v) > s["maxLength"]:
            errs.append(f"{where}: too long")
        if "pattern" in s and not re.search(s["pattern"], v):
            errs.append(f"{where}: pattern")
    elif t == "integer":
        if not isinstance(v, int) or isinstance(v, bool):
            errs.append(f"{where}: not an integer")
        elif "minimum" in s and v < s["minimum"]:
            errs.append(f"{where}: below minimum")
    elif t == "number":
        if not isinstance(v, (int, float)) or isinstance(v, bool):
            errs.append(f"{where}: not a number")
        elif "minimum" in s and v < s["minimum"]:
            errs.append(f"{where}: below minimum")
    return errs


# ------------------------------------------------------------------------------------------- allow-list ---
def _free_text_ok(s: str, max_len: int) -> bool:
    clean, red = guard().scrub(s, max_len=max_len)
    return clean == re.sub(r"\s+", " ", s).strip() and not red


def _name_ok(s: str, rx: re.Pattern) -> bool:
    if not isinstance(s, str) or not rx.match(s):
        return False
    from capture.hook import CRED
    return not CRED.search(s) and not any(LONG_TOKEN.search(seg) for seg in re.split(r"__|:|-", s))


def _num_ok(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) and x >= 0


def check_label(lab, tier: str) -> list[str]:
    """Problems with a label (empty = ok). Shape: exactly {text, category, source}; text 1-40 characters of letters,
    digits, spaces and & + - (no . / : @ _ quotes, so no path, file, domain, address or id); no run of 3+ digits;
    guard-clean and unchanged by the guard. A label from the heuristic is one of its fixed PHRASES; one from a model,
    and ANY label at the metadata tier, uses only generic VOCAB words; only a user's label at the rich tier is free
    text (the project_name rules)."""
    if not isinstance(lab, dict) or set(lab) != {"text", "category", "source"}:
        return ["label shape"]
    bad = []
    t, c, src = lab["text"], lab["category"], lab["source"]
    if c not in L.categories():
        bad.append("label category")
    if src not in L.SOURCES:
        bad.append("label source")
    if not (isinstance(t, str) and L.TEXT_RE.match(t) and t == " ".join(t.split()) and len(t) <= L.MAX_LEN
            and not L.NUMBER_RUN.search(t) and _free_text_ok(t, L.MAX_LEN)):
        return bad + ["label text"]
    from capture.hook import CRED
    if CRED.search(t) or LONG_TOKEN.search(t):
        bad.append("label text")
    if src == "heuristic" and t not in L.HEURISTIC_TEXTS:
        bad.append("label text not a heuristic phrase")
    if (src != "user" or tier != "rich") and L.unknown_words(t):
        bad.append("label words")
    return bad


def check_manifest(m: dict, canaries=()) -> None:
    errs = validate_schema(m, schema())
    if errs:
        raise Rejected("schema: " + "; ".join(errs[:5]))
    tier = m["privacy_tier"]
    rich = tier == "rich"
    bad: list[str] = []
    if m["user_id"] != "local":
        bad.append("user_id")
    if not C.HEX16.match(m["project_id"]):
        bad.append("project_id")
    if "project_name" in m and not (rich and NAME_RICH.match(m["project_name"])
                                    and _free_text_ok(m["project_name"], 60)):
        bad.append("project_name")
    if "summary" in m:
        s = m["summary"]
        if not (rich and len(s.split()) <= 60 and _free_text_ok(s, 420)):
            bad.append("summary")
    if "label" in m:
        bad += check_label(m["label"], tier)
    for i, a in enumerate(m["agents"]):
        r = a["role"]
        ok = r in BUILTIN_ROLES or bool(ROLE_META.match(r))
        if not ok:
            bad.append(f"agents[{i}].role")
        if not (_num_ok(a["turns"]) and _num_ok(a["minutes"])):
            bad.append(f"agents[{i}] numbers")
    for k, n in m["tools"].items():
        if not (_name_ok(k, TOOL_RICH) if rich else TOOL_META.match(k)) or not _num_ok(n):
            bad.append(f"tools key {k[:12]!r}")
    for k in ("skills", "infra_tags"):
        if m[k]:
            bad.append(k)  # capture never derives these (there is no user back-fill)
    for x in m["mcp_servers"]:
        if not SRV_META.match(x):
            bad.append("mcp_servers")
    for x in m["links_to"]:
        if not C.HEX16.match(x):
            bad.append("links_to")
    r = m["runs"]
    if not (MINUTE_TS.match(r["first_at"]) and MINUTE_TS.match(r["last_at"]) and _num_ok(r["count"])
            and _num_ok(r["total_minutes"])):
        bad.append("runs")
    if not all(_num_ok(v) for v in m["outcomes"].values()):
        bad.append("outcomes")
    if bad:
        raise Rejected("allow-list: " + ", ".join(sorted(set(bad))[:8]))
    _canaries(C.canonical(m), canaries)


def _canaries(b: bytes, canaries) -> None:
    low = b.decode("ascii").lower()
    hits = [c for c in canaries if c and c.lower() in low]
    if hits:
        raise Rejected(f"canary present ({len(hits)})")


def envelope(manifest: dict, visibility: str) -> dict:
    return {"schema": ENVELOPE_SCHEMA, "visibility": visibility, "manifest": manifest}


def subagent_runs_claimed(m: dict) -> int:
    """Subagent runs the manifest's own rows claim (non-orchestrator, non-fork `turns`; the server counts agents the same way)."""
    return sum(int(a["turns"]) for a in m["agents"] if a["role"] not in ("orchestrator", "fork"))


def attestation_message(env: dict) -> bytes:
    """The bytes the attestation MAC covers: the sha256 of the canonical UNSIGNED envelope (schema v1, visibility,
    manifest: so the project id, every count and the visibility are bound), the signing key id and the sorted run ids."""
    unsigned = {k: env[k] for k in ENVELOPE_KEYS}
    a = env["attestation"]
    return C.canonical({"body": hashlib.sha256(C.canonical(unsigned)).hexdigest(), "key": a["key"],
                        "runs": a["runs"], "v": a["v"]})


def sign_envelope(env: dict, runs, key_id: str, key: bytes) -> dict:
    """A v1 envelope: `env` plus an attestation over the hook-recorded run ids, MACed with the server-minted
    per-token signing key (upload.py). Only the plugin holds the key on the client side (threat model: README)."""
    out = {"schema": ENVELOPE_SCHEMA_SIGNED, "visibility": env["visibility"], "manifest": env["manifest"],
           "attestation": {"v": 1, "key": key_id, "runs": sorted(set(runs)), "sig": ""}}
    out["attestation"]["sig"] = base64.urlsafe_b64encode(
        hmac.new(key, attestation_message(out), hashlib.sha256).digest()).rstrip(b"=").decode("ascii")
    return out


def _check_attestation(env: dict) -> None:
    a = env.get("attestation")
    if not isinstance(a, dict) or set(a) != ATTEST_KEYS or a["v"] != 1:
        raise Rejected("attestation shape")
    if not (isinstance(a["key"], str) and ATTEST_KEY_RE.match(a["key"]) and isinstance(a["sig"], str)
            and ATTEST_SIG_RE.match(a["sig"])):
        raise Rejected("attestation fields")
    r = a["runs"]
    if not (isinstance(r, list) and len(r) <= MAX_RUNS and all(isinstance(x, str) and RUN_ID_RE.match(x) for x in r)
            and r == sorted(set(r))):
        raise Rejected("attestation runs")


def check_envelope(env, canaries=()) -> bytes:
    """Validate and return the exact bytes that would leave. Re-parses the bytes, so what is checked is what is sent.
    v0 (unsigned) = exactly {schema, visibility, manifest}; v1 (signed) adds `attestation`, whose run ids may not
    outnumber the subagent runs the rows claim (ledger-only runs are display rows the hook never saw)."""
    if not isinstance(env, dict):
        raise Rejected("envelope keys")
    signed = env.get("schema") == ENVELOPE_SCHEMA_SIGNED
    if set(env) != (ENVELOPE_KEYS | {"attestation"} if signed else ENVELOPE_KEYS):
        raise Rejected("envelope keys")
    if env["schema"] not in (ENVELOPE_SCHEMA, ENVELOPE_SCHEMA_SIGNED) or env["visibility"] not in C.VISIBILITY:
        raise Rejected("envelope fields")
    if signed:
        _check_attestation(env)
    try:
        b = C.canonical(env)  # NaN / Infinity / non-JSON values are refused here
        back = json.loads(b)
    except (ValueError, TypeError) as e:
        raise Rejected(f"not canonical JSON: {type(e).__name__}") from None
    if C.canonical(back) != b:
        raise Rejected("bytes do not round-trip")
    if back["visibility"] == "private" and back["manifest"].get("privacy_tier") != "metadata":
        raise Rejected("a private project leaves at the metadata tier only")
    check_manifest(back["manifest"], canaries)
    if signed and len(back["attestation"]["runs"]) > subagent_runs_claimed(back["manifest"]):
        raise Rejected("attestation runs exceed the claimed subagent runs")
    _canaries(b, canaries)
    return b
