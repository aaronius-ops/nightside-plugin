#!/usr/bin/env python3
"""/planet. Only `upload --confirm <sha256>` with a configured server can open a network connection
(capture/upload.py); every other subcommand is local.

  planet.py name <Name>                          keep your planet's name locally (reserving it needs the server)
  planet.py privacy rich|metadata|public|private [--name <project name>]
                                                 --name: the only project name that can ever leave (rich tier)
  planet.py privacy rich|metadata [--here] [--summary|--no-summary]
                                                 manifest tier (default for all projects, or --here for this one);
                                                 --summary opts in to the rich tier's LLM summary (rich.py)
  planet.py privacy public|private [--default]   this project's visibility (or, with --default, new projects')
  planet.py invite | open                        not in the plugin yet: use the Nightside site
  planet.py status [--survey] [--rich] [--json]  what has been captured locally; --survey refreshes the manifests
  planet.py preview [--label "..."] [--category <c>]
                                                 the exact bytes that would leave, per project, with sha256, and
                                                 each project's PUBLIC LABEL; --label / --category set this
                                                 project's label first (validated; --label auto resets it)
  planet.py upload [--confirm <sha256>]          the consent step: --confirm checks the bytes the last preview
                                                 SAVED and, only if a server is configured, sends exactly them
  planet.py withdraw [--confirm <project id>]    take a project back: the server deletes every manifest of it you
                                                 uploaded, and the project is set private here. Without --confirm it
                                                 only prints this directory's project id and what would happen
  planet.py remote show | set <base URL> | token [--file F] | clear
                                                 the Nightside server (no default) and your upload token (read
                                                 from --file or stdin, kept 600 in the capture root, never printed)
  planet.py backfill | import                    refused: there is no back-fill. A planet grows only from capture
                                                 going forward
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from capture import common as C  # noqa: E402
from capture import consent as K  # noqa: E402
from capture import surveyor as S  # noqa: E402
from capture import signing as SK  # noqa: E402
from capture import upload as U  # noqa: E402  (endpoint/token config; send() is only reached via consent.upload)

NOT_YET = "not available from the plugin yet; use your planet's page on the Nightside site. Nothing was sent."
NO_BACKFILL = ("there is no back-fill: islands come only from what this plugin captures from now on, one per project "
               "you work in with it. Past sessions, repos and transcripts are never imported. "
               "Nothing was imported.")


def _here(root: Path) -> tuple[str | None, Path | None]:
    d = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    try:
        pid, _ = C.project_identity(C.install_key(root), d)
        return pid, d
    except Exception:  # noqa: BLE001
        return None, d


def _uploaded(root: Path) -> int:
    """Confirmed uploads the server acknowledged (local log written by consent.upload)."""
    try:
        lines = (root / K.SENT_LOG).read_text(encoding="utf-8").splitlines()
    except OSError:
        return 0
    n = 0
    for line in lines:
        try:
            n += json.loads(line).get("ok") is True
        except ValueError:
            pass
    return n


def cmd_remote(a, cfg, root) -> int:
    """Local configuration only: no subcommand here opens a connection."""
    if a.action == "set":
        try:
            base, warn = U.check_endpoint(a.url or "")
        except U.BadEndpoint as e:
            print(f"not saved: {e}", file=sys.stderr)
            return 2
        cfg["upload_endpoint"] = base
        C.save_config(cfg)
        print(f"Nightside server saved: {base}" + (f"\nwarning: {warn}" if warn else ""))
        return 0
    if a.action == "token":
        try:
            raw = Path(a.file).expanduser().read_text(encoding="ascii") if a.file else sys.stdin.readline()
            d = U.save_token(root, raw)
        except (OSError, ValueError, UnicodeError) as e:
            print(f"not saved: {e}", file=sys.stderr)
            return 2
        print(f"Upload token saved (key {d.get('kid')}, planet {d.get('planet')}); it is never printed. "
              + ("Manifests will be signed." if d.get("signed") else
                 "This is a bare nsu1 token: uploads are unsigned and never published; paste the nsu2 credential."))
        return 0
    if a.action == "clear":
        cfg["upload_endpoint"] = None
        C.save_config(cfg)
        U.clear_token(root)
        SK.clear_signing_key(root)
        print("Server and token cleared: nothing can be uploaded.")
        return 0
    tok = U.load_token(root)
    d = U.describe(tok) if tok else {}
    print(f"server: {cfg.get('upload_endpoint') or '(none: upload is not enabled)'}")
    print(f"token: {'saved (key ' + str(d.get('kid')) + ', planet ' + str(d.get('planet')) + ')' if tok else '(none)'}")
    print("upload: " + ("on after each --confirm" if U.configured(cfg, root) else "not enabled"))
    return 0


def cmd_withdraw(a, cfg, root) -> int:
    """Without --confirm: local only (prints the id and what a confirm would do). With it: consent.withdraw."""
    if not a.confirm:
        here, _ = _here(root)
        remote = (U.configured(cfg, root) or (None,))[0]
        print(f"This directory's project id: {here or '(none)'}.")
        print("Withdraw asks " + (remote or "the Nightside server (none configured)") + " to delete every manifest of "
              "that project you uploaded, and sets it private here. To go ahead: /planet withdraw --confirm <project id>"
              ". Nothing was sent.")
        return 0
    known = set(S.projects(root)) | {f.stem for f in (root / "outbox").glob("*.envelope")}
    rc, msg = K.withdraw(root, cfg, a.confirm, sorted(known))
    print(msg)
    return rc


def cmd_status(a, cfg, root) -> int:
    here, _ = _here(root)
    idx = C.read_index(root)
    if a.survey:
        S.retention(root, cfg)
        for pid in S.projects(root):
            summary = None
            if a.rich and pid == here:
                from capture import rich
                m = S.survey(root, pid, cfg)
                ok, why = rich.opted_in(cfg, m)
                summary = rich.summarize(m) if ok else None
                print(f"rich summary: {'added' if summary else 'none'} ({why if not ok else 'model answer checked'})")
            try:
                S.survey_to_outbox(root, pid, cfg, summary=summary)
            except Exception as e:  # noqa: BLE001
                print(f"survey blocked for {pid}: {e}")
    rows = []
    for pid in S.projects(root):
        ev = S.read_spool(root, pid)
        parts = S.load_partials(root, pid)
        tier, vis = S.effective_privacy(cfg, pid)
        ob = root / "outbox" / f"{pid}.json"
        rows.append({"project_id": pid, "local_name": (idx.get(pid) or {}).get("name"), "this_project": pid == here,
                     "sessions": len(parts), "events_in_spool": len(ev),
                     "tool_calls": sum(sum((p.get("tools") or {}).values()) for p in parts.values()),
                     "subagents": sum(len(p.get("subs") or {}) for p in parts.values()),
                     "last_event": S._minute(max(p["last"] for p in parts.values())) if parts else None,
                     "project_name": ((cfg.get("projects") or {}).get(pid) or {}).get("name"),
                     "tier": tier, "visibility": vis,
                     "manifest_bytes": ob.stat().st_size if ob.is_file() else None})
    info = {"capture": "on" if C.enabled(cfg) else "off", "root": str(root), "planet_name": cfg.get("planet_name"),
            "default_tier": cfg["privacy_tier"], "default_visibility": cfg["default_visibility"],
            "rich_summary": cfg.get("rich_summary") is True, "projects": rows, "uploaded": _uploaded(root),
            "remote": (U.configured(cfg, root) or (None,))[0]}
    if a.json:
        print(json.dumps(info, indent=1))
        return 0
    print(f"Nightside capture: {info['capture']}  (local spool {root}; "
          f"{'uploads only what you confirm, to ' + info['remote'] if info['remote'] else 'nothing is uploaded'})")
    print(f"planet name: {info['planet_name'] or '(not set)'}   default tier: {info['default_tier']}   "
          f"new projects: {info['default_visibility']}   rich summary: {'on' if info['rich_summary'] else 'off'}")
    if not rows:
        print("No sessions captured yet.")
    for r in rows:
        mark = "*" if r["this_project"] else " "
        print(f"{mark} {r['project_id']}  {r['local_name'] or '(unnamed)':<24} {r['visibility']:<7} {r['tier']:<8} "
              f"sessions {r['sessions']:>3}  tool calls {r['tool_calls']:>5}  subagents {r['subagents']:>3}  "
              f"last {r['last_event'] or '-'}  manifest {r['manifest_bytes'] or '-'} B")
    if info["uploaded"]:
        print(f"Uploaded: {info['uploaded']} confirmed manifest(s) to {info['remote']}. See what would leave next: /planet preview")
    else:
        print("Uploaded: nothing" + ("" if info["remote"] else " (upload is not enabled)") +
              ". See exactly what would leave: /planet preview")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="/planet", description="Nightside planet (local only)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("name")
    p.add_argument("name", nargs="+")
    p = sub.add_parser("privacy")
    p.add_argument("setting", choices=["rich", "metadata", "public", "private"])
    p.add_argument("--here", action="store_true")
    p.add_argument("--default", action="store_true")
    p.add_argument("--name", help="the project name that may leave at the rich tier (yours to choose)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--summary", action="store_true")
    g.add_argument("--no-summary", action="store_true")
    sub.add_parser("invite")
    sub.add_parser("open")
    p = sub.add_parser("status")
    p.add_argument("--survey", action="store_true")
    p.add_argument("--rich", action="store_true")
    p.add_argument("--json", action="store_true")
    for name in ("preview", "upload"):
        p = sub.add_parser(name)
        p.add_argument("--label", help='this project\'s public label, <= 40 chars ("auto" = the one made here)')
        p.add_argument("--category", help="this project's category (the builder's vocabulary)")
        if name == "upload":
            p.add_argument("--confirm")
    p = sub.add_parser("withdraw")
    p.add_argument("--confirm", help="the project id to withdraw (from /planet status or the preview)")
    for name in ("backfill", "import"):
        p = sub.add_parser(name)
        p.add_argument("rest", nargs="*")
    p = sub.add_parser("remote")
    p.add_argument("action", choices=["show", "set", "token", "clear"])
    p.add_argument("url", nargs="?")
    p.add_argument("--file")
    a = ap.parse_args(argv)
    os.umask(0o077)
    cfg = C.load_config()
    if a.cmd in ("invite", "open"):
        print(f"/planet {a.cmd}: {NOT_YET}")
        return 0
    if a.cmd in ("backfill", "import"):
        print(f"/planet {a.cmd}: {NO_BACKFILL}", file=sys.stderr)
        return 2
    try:
        root = C.ensure_root(C.capture_root(cfg))
    except C.Refused as e:
        print(f"capture root refused: {e}", file=sys.stderr)
        return 2
    if a.cmd == "name":
        try:
            n = K.set_planet_name(cfg, " ".join(a.name))
        except ValueError as e:
            print(e, file=sys.stderr)
            return 2
        C.save_config(cfg)
        print(f"Planet name saved locally: {n}. Reserving it on Nightside is {NOT_YET}")
        return 0
    if a.cmd == "privacy":
        here, _ = _here(root)
        if a.name is not None:
            if not here:
                print("no current project", file=sys.stderr)
                return 2
            try:
                K.set_project_name(cfg, here, a.name)
            except ValueError as e:
                print(e, file=sys.stderr)
                return 2
        if a.setting in C.TIERS:
            K.set_tier(cfg, a.setting, here if a.here else None)
            if a.summary or a.no_summary:
                cfg["rich_summary"] = bool(a.summary)
            scope = "this project" if a.here else "all projects without their own setting"
        else:
            K.set_visibility(cfg, a.setting, None if a.default else here)
            scope = "new projects" if a.default else "this project"
        C.save_config(cfg)
        tier, vis = S.effective_privacy(cfg, here) if here else (cfg["privacy_tier"], cfg["default_visibility"])
        print(f"Saved: {a.setting} for {scope}. This project now: {vis}, {tier} tier"
              f"{' (private projects are always metadata)' if vis == 'private' else ''}; "
              f"rich summary {'on' if cfg.get('rich_summary') is True else 'off'}.")
        return 0
    if a.cmd == "status":
        return cmd_status(a, cfg, root)
    if a.cmd == "remote":
        return cmd_remote(a, cfg, root)
    if a.cmd == "withdraw":
        return cmd_withdraw(a, cfg, root)
    if a.label is not None or a.category is not None:
        if a.cmd == "upload" and a.confirm:
            print("a label change makes new bytes: run /planet preview --label ... first, then confirm its sha256",
                  file=sys.stderr)
            return 2
        here, _ = _here(root)
        if not here:
            print("no current project", file=sys.stderr)
            return 2
        try:
            lab = K.set_label(cfg, root, here, a.label, a.category)
        except ValueError as e:
            print(f"label refused: {e}", file=sys.stderr)
            return 2
        C.save_config(cfg)
        print(f"Label for this project saved locally: {lab if lab else 'auto (made on this machine)'}")
    if a.cmd == "preview" or (a.cmd == "upload" and not a.confirm):
        print(K.render(K.preview(root, cfg), (U.configured(cfg, root) or (None,))[0]))
        return 0
    rc, msg = K.upload(root, cfg, a.confirm)  # the saved bytes the user saw; never a fresh survey
    print(msg)
    return rc


if __name__ == "__main__":
    sys.exit(main())
