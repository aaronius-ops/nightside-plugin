"""Consent and privacy settings, the confirmed upload and withdraw. Nothing leaves unless the user configured a server
(`/planet remote`) AND confirmed the exact saved bytes; the send itself lives in upload.py (the plugin's one network path).

Settings (config file, see common.py), all local:
  privacy_tier        "metadata" (default) | "rich"       /planet privacy rich|metadata [--here]
  default_visibility  "private" (default) | "public"      /planet privacy public|private --default
  projects[<id>]      {"visibility", "tier", "name", "category", "label"}   /planet privacy public|private (this project)
                      "name" is the ONLY project name that can ever leave (rich tier): /planet privacy ... --name X
                      "label" {"text", "category"}: the user's public label (labels.py), set with
                      /planet preview --label "..." --category <c> (validated now and again at every survey);
                      --label auto goes back to the label made on this machine
  planet_name         /planet name <Name> (kept locally; reserving it needs the server)
  rich_summary        false (default); true opts in to rich.py's LLM summary (rich tier + public projects only)
A private project always leaves at the metadata tier: no project name, no summary, hashed agent / MCP names.

The consent design for the upload: for each project, the preview prints the visibility, tier,
byte count, sha256 and then THE EXACT BYTES, verbatim, that the request body would carry. The user answers y/n per
project. The preview saves exactly those bytes to outbox/<project_id>.envelope (600). A "y" is bound to their sha256
(`/planet upload --confirm <sha256>`): confirm re-reads the SAVED bytes, re-checks them against the allow-list and
compares the hash, and upload() sends exactly those bytes (only when a server is configured; otherwise nothing leaves).
Confirm never re-surveys (the session's own activity after the preview must not change what was approved); a new
preview replaces the saved bytes. The Authorization header carries the upload token, never manifest data.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

from capture import common as C
from capture import allowlist as A
from capture import labels as L
from capture import surveyor as S
from capture import signing as SK  # local key file only; no network

UPLOAD_DISABLED = ("Upload is not enabled: no Nightside server and upload token are configured (/planet remote). "
                   "Nothing left this machine: no network call was made.")
SENT_LOG = "sent.jsonl"
PLANET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 '._-]{0,39}$")


def set_planet_name(cfg: dict, name: str) -> str:
    name = re.sub(r"\s+", " ", name or "").strip()
    if not PLANET_NAME.match(name) or not A._free_text_ok(name, 40):
        raise ValueError("a planet name is 1-40 letters, digits, spaces, ' . _ - (no e-mail, URL, path or secret)")
    cfg["planet_name"] = name
    return name


def set_project_name(cfg: dict, pid: str, name: str) -> str:
    name = re.sub(r"\s+", " ", name or "").strip()
    if not A.NAME_RICH.match(name) or not A._free_text_ok(name, 60):
        raise ValueError("a project name is 1-60 letters, digits, spaces, . _ - (no e-mail, URL, path or secret)")
    cfg.setdefault("projects", {}).setdefault(pid, {})["name"] = name
    return name


def set_label(cfg: dict, root: Path, pid: str, text: str | None, category: str | None) -> dict | None:
    """The user's label for this project. text "auto" (or both None) clears it. Validated as the allow-list will
    validate it for the project's current tier, plus the local-name check; raises ValueError with the reason."""
    p = cfg.setdefault("projects", {}).setdefault(pid, {})
    if (text or "").strip().lower() == "auto" or (text is None and category is None):
        p.pop("label", None)
        return None
    if category is not None and category not in L.categories():
        raise ValueError("category is one of: " + ", ".join(L.categories()))
    lab = dict(p.get("label") or {})
    if text is not None:
        lab["text"] = re.sub(r"\s+", " ", text).strip()
        if not lab["text"]:
            raise ValueError("an empty label: give 1-40 characters, or --label auto for the one made here")
    if category is not None:
        lab["category"] = category
    tier, _ = S.effective_privacy(cfg, pid)
    trial = {"text": lab.get("text") or L.default_text(lab.get("category") or "unclassified"),
             "category": lab.get("category") or "unclassified", "source": "user"}
    bad = A.check_label(trial, tier)
    if "label words" in bad:
        raise ValueError(f"at the {tier} tier a label uses only generic words; not allowed: "
                         + ", ".join(L.unknown_words(trial["text"])[:6]) + " (see label_vocab.json)")
    if bad:
        raise ValueError("a label is 1-40 letters, digits, spaces, & + - (no file, path, address, number or secret)")
    if L.mentions_local_name(trial["text"], L.local_names(root, pid)):
        raise ValueError("the label repeats a local name (the repo, a tool server, an agent or your login)")
    p["label"] = {k: lab[k] for k in ("text", "category") if lab.get(k)}
    return p["label"]


def set_tier(cfg: dict, tier: str, pid: str | None = None) -> None:
    if tier not in C.TIERS:
        raise ValueError("tier is rich or metadata")
    if pid:
        cfg.setdefault("projects", {}).setdefault(pid, {})["tier"] = tier
    else:
        cfg["privacy_tier"] = tier


def set_visibility(cfg: dict, vis: str, pid: str | None = None) -> None:
    if vis not in C.VISIBILITY:
        raise ValueError("visibility is public or private")
    if pid:
        cfg.setdefault("projects", {}).setdefault(pid, {})["visibility"] = vis
    else:
        cfg["default_visibility"] = vis


def _carried_summary(root: Path, pid: str, cfg: dict) -> dict | None:
    """Keep a rich summary already in the outbox only while the project is still rich (it is re-checked anyway)."""
    tier, _ = S.effective_privacy(cfg, pid)
    if tier != "rich":
        return None
    try:
        old = json.loads((root / "outbox" / f"{pid}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(old, dict) or "summary" not in old:
        return None
    out = {k: old[k] for k in ("summary", "category") if k in old}
    if (old.get("label") or {}).get("source") == "claude":
        out["label"] = old["label"]
    return out


def _envelope_path(root: Path, pid: str) -> Path:
    return root / "outbox" / f"{pid}.envelope"


def preview(root: Path, cfg: dict, pids=None, canaries=()) -> list[dict]:
    """What would leave, per project: re-surveyed now, allow-listed, as exact bytes, SAVED for --confirm.
    Fails closed per project (a blocked project has no saved envelope)."""
    items = []
    names = C.read_names(root)
    for pid in (pids or S.projects(root)):
        it = {"project_id": pid, "local_name": (C.read_index(root).get(pid) or {}).get("name")}
        ep = _envelope_path(root, pid)
        try:
            runs: list[str] = []
            S.survey_to_outbox(root, pid, cfg, summary=_carried_summary(root, pid, cfg), runs_out=runs)
            m = json.loads((root / "outbox" / f"{pid}.json").read_text(encoding="utf-8"))
            tier, vis = S.effective_privacy(cfg, pid)
            env = A.envelope(m, vis)
            sk = SK.load_signing_key(root)
            runs = runs[:A.subagent_runs_claimed(m)]  # never more ids than the rows claim (the allow-list refuses that)
            if sk:  # sign the exact manifest being saved: the MAC covers these bytes (allowlist.attestation_message)
                env = A.sign_envelope(env, runs, sk[0], sk[1])
            b = A.check_envelope(env, canaries)
            C.atomic_write(ep, b)
            it.update(signed=bool(sk), attested_runs=len(runs) if sk else None, visibility=vis, tier=tier, bytes=b, sha256=hashlib.sha256(b).hexdigest(), label=m.get("label"),
                      legend={h: names[h] for h in sorted(names) if h in b.decode("ascii")
                              or h.replace("srv-", "mcp-") in b.decode("ascii")
                              or ("__" + h[4:] + "__") in b.decode("ascii")})
        except A.Rejected as e:
            try:
                ep.unlink()
            except OSError:
                pass
            it.update(rejected=str(e))
        items.append(it)
    return items


def saved(root: Path) -> list[dict]:
    """The envelopes the last preview saved, re-checked (a tampered or stale-schema file is refused)."""
    items = []
    ob = root / "outbox"
    for ep in sorted(ob.glob("*.envelope")) if ob.is_dir() else []:
        if ep.is_symlink() or not C.HEX16.match(ep.stem):
            continue
        b = ep.read_bytes()
        try:
            if A.check_envelope(json.loads(b)) != b:
                raise A.Rejected("saved bytes are not canonical")
            items.append({"project_id": ep.stem, "bytes": b, "sha256": hashlib.sha256(b).hexdigest()})
        except (A.Rejected, ValueError) as e:
            items.append({"project_id": ep.stem, "rejected": str(e)})
    return items


def render(items: list[dict], remote: str | None = None) -> str:
    """remote = the configured base URL (None: upload not enabled, the preview says so)."""
    head = (f"WHAT WOULD LEAVE THIS MACHINE (nothing has yet; a confirmed project goes to {remote} only)" if remote
            else "WHAT WOULD LEAVE THIS MACHINE (nothing has; upload is not enabled)")
    out = [head, ""]
    if not items:
        out.append("No captured projects yet.")
    for it in items:
        label = it.get("local_name") or "(unnamed)"
        out.append(f"== project {it['project_id']}  local name: {label} (the local name is shown here only)")
        if "rejected" in it:
            out.append(f"   BLOCKED by the allow-list: {it['rejected']}. Nothing from this project would be sent.")
            out.append("")
            continue
        out.append(f"   visibility: {it['visibility']}   tier: {it['tier']}   {len(it['bytes'])} bytes   "
                   f"sha256 {it['sha256']}")
        if it.get("signed"):
            out.append(f"   SIGNED by this plugin: {it['attested_runs']} subagent run(s) recorded by the hook (random run ids "
                       "below; the signing key itself is never sent)")
        else:
            out.append("   UNSIGNED (no signing key: paste the nsu2 credential, /planet remote token). The server stores it but never "
                       "publishes it: the agent count is not attested")
        lab = it.get("label")
        if lab:
            out.append(f"   PUBLIC LABEL: \"{lab['text']}\"   category: {lab['category']}   (made by: {lab['source']})")
        else:
            out.append("   PUBLIC LABEL: none (no candidate passed the checks); the builder classifies from counts")
        out.append('   change it: /planet preview --label "<= 40 chars" --category <category>   (--label auto resets)')
        out.append("   exact request body:")
        out.append(it["bytes"].decode("ascii"))
        if it.get("legend"):
            out.append("   local legend (shown to you only, never sent): " +
                       ", ".join(f"{h} = {n}" for h, n in it["legend"].items()))
        out.append(f"   Send these {len(it['bytes'])} bytes for this project? [y/N]  "
                   f"(a yes is `/planet upload --confirm {it['sha256'][:16]}`)")
        out.append("")
    out.append(f"Nothing has been sent. A yes sends exactly those bytes to {remote}." if remote else UPLOAD_DISABLED)
    return "\n".join(out)


def select(items: list[dict], sha_prefix: str) -> tuple[int, str | None, dict | None]:
    """items = saved(root): the bytes the user was shown. Never a fresh survey."""
    sha_prefix = (sha_prefix or "").lower()
    if not re.fullmatch(r"[0-9a-f]{16,64}", sha_prefix):
        return 2, "confirm with the sha256 (at least 16 hex characters) printed by the preview", None
    hit = [it for it in items if it.get("sha256", "").startswith(sha_prefix)]
    if not hit:
        return 3, ("No saved preview has that sha256 (a newer preview replaced it, or it was never shown). "
                   "Run the preview again."), None
    return 0, None, hit[0]


def confirm(items: list[dict], sha_prefix: str) -> tuple[int, str]:
    """The local half of the consent step: is this a hash the user was shown? No network."""
    rc, msg, it = select(items, sha_prefix)
    if rc:
        return rc, msg
    return 0, f"Confirmed {len(it['bytes'])} bytes for project {it['project_id']}. " + UPLOAD_DISABLED


SERVER_SAYS = {
    404: "the server did not accept it (uploads are off there, or the token is not valid for it; ask the owner)",
    413: "the server refused it as too large",
    415: "the server refused the content type",
    422: "the server rejected the bytes",
    429: "the server is rate limiting uploads; try again later",
    503: "the server could not store it right now; try again later",
}


def upload(root: Path, cfg: dict, sha_prefix: str) -> tuple[int, str]:
    """/planet upload --confirm <sha256>: confirm locally, then (only with a configured server and token) send exactly
    the saved bytes. Without a server: the local confirm message and no network call."""
    rc, msg, it = select(saved(root), sha_prefix)
    if rc:
        return rc, msg
    from capture import upload as U
    remote = U.configured(cfg, root)
    if remote is None:
        return 0, f"Confirmed {len(it['bytes'])} bytes for project {it['project_id']}. " + UPLOAD_DISABLED
    base, token = remote
    b = A.check_envelope(json.loads(it["bytes"]))  # the gate, once more, on the exact bytes that leave
    if b != it["bytes"]:
        return 4, "The saved bytes are not canonical; run the preview again. Nothing was sent."
    ok_server, rc, msg = U.check_server(base)  # the plugin must be at least the server's min_version
    if not ok_server:
        return rc, msg
    status, resp = U.send(base, token, b)
    ok = status in (200, 201) and resp.get("sha256") == it["sha256"]
    C.append_line(root / SENT_LOG, C.canonical({"sha256": it["sha256"], "project_id": it["project_id"],
                                                "status": status, "ok": ok, "t": int(time.time())}) + b"\n")
    if ok:
        what = "stored" if resp.get("status") == "stored" else "already there (same bytes)"
        return 0, f"Sent {len(b)} bytes for project {it['project_id']} to {base}: {what}. sha256 {it['sha256']}"
    if status == 0:
        return 5, f"Could not reach {base} ({resp.get('error', 'network error')}). Nothing was stored; try again."
    why = SERVER_SAYS.get(status, f"the server answered {status}")
    if status == 422 and resp.get("reason"):
        why += f" ({resp['reason']})"
    if status == 422 and resp.get("reason") == "unsigned" and isinstance(resp.get("message"), str):
        why = resp["message"][:300].rstrip(".")  # the server names the plugin version it needs
    return 6, f"Not uploaded: {why}."


def withdraw(root: Path, cfg: dict, project_id: str, known: list[str]) -> tuple[int, str]:
    """/planet withdraw --confirm <project id>: ask the configured server to delete every manifest of that project
    this token's user uploaded. The id must be one of this machine's captured projects (`known`), so a typo cannot
    reach the network. Locally the project is also set private, so a later preview of it is private by default.
    Exit codes as upload(): 2 bad id, 0 done (or nothing configured), 5 no answer, 6 the server said no."""
    pid = (project_id or "").strip().lower()
    if not C.HEX16.match(pid) or pid not in known:
        return 2, "Not a project captured on this machine. Run /planet status to see the ids. Nothing was sent."
    set_visibility(cfg, "private", pid)
    C.save_config(cfg)
    from capture import upload as U
    remote = U.configured(cfg, root)
    if remote is None:
        return 0, (f"Project {pid} set private locally. No Nightside server and upload token are configured, so "
                   "there is nothing on a server to withdraw from here. Nothing was sent.")
    base, token = remote
    status, resp = U.withdraw_project(base, token, pid)
    C.append_line(root / SENT_LOG, C.canonical({"withdrawn": pid, "status": status, "t": int(time.time())}) + b"\n")
    if status == 200 and resp.get("status") == "withdrawn":
        n = resp.get("deleted") if isinstance(resp.get("deleted"), int) else 0
        return 0, (f"Withdrawn: {n} uploaded manifest(s) of project {pid} deleted from {base}. The island leaves your "
                   "planet at the server's next publish. The project is now private here; nothing uploads unless you "
                   "preview and confirm again.")
    if status == 0:
        return 5, f"Could not reach {base} ({resp.get('error', 'network error')}). Nothing was withdrawn; try again."
    why = SERVER_SAYS.get(status, f"the server answered {status}")
    return 6, f"Not withdrawn: {why}. The project is private here."
