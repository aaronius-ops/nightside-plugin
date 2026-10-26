"""The ledger's privacy guard. Fails closed.

Every free-text value the ledger writes (the Agent `description`, a branch name) passes `scrub()`. A span that hits
a deny class becomes "[redacted]"; anything the guard cannot judge (a non-string, a guard error) becomes None.
`check_row()` then scans the whole row for credential shapes and raises, so a bad row is never written.

Classes: built-in generic ones (credentials, emails, URLs, hostnames, IPs, phones, money amounts, home-directory
paths) plus, optionally, a project deny file:
  --deny path/to/deny.py    a module defining DENY = {class: [regex, ...]} (and optionally HARD_CLASSES, ALLOW,
                            CASE_SENSITIVE), e.g. a project's tools/deny.py
  --deny path/to/deny.json  {"classes": {class: [regex, ...]}, "allow": [regex, ...]}
Every class in the deny file is applied, except those it lists in LEDGER_SKIP / "ledger_skip" (the CLI's
--deny-skip adds more). A deny file that fails to load, or loads an empty class, is an error: the CLI stops instead
of writing an unguarded ledger. With NO deny file a description is never free text: it becomes the run's kind
("build", "review", ...), because a blocklist without the project's own names and deal terms cannot judge it.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

REDACTED = "[redacted]"

GENERIC = {
    "secret": [r"\bsk-(?:ant-|proj-|svcacct-)?[\w-]{16,}", r"\bAIza[0-9A-Za-z_-]{20,}", r"\bya29\.[\w-]{10,}",
               r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{10,})", r"\bglpat-[\w-]{10,}", r"\bxox[abposr]-[\w-]{8,}",
               r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", r"-----BEGIN", r"\b(?:bearer|token|password|passwd|secret)\s*[:=]\s*\S+",
               r"\b[A-Za-z0-9+/_-]{40,}={0,2}"],
    "contact": [r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", r"(?<!\d)\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)"],
    "net": [r"\b[a-z][a-z0-9+.-]*://\S+", r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
            r"\b(?:[a-z0-9-]+\.)+(?:io|com|net|org|app|dev|ai|co|us|cloud|xyz|me|sh|edu|internal|local)\b"],
    "amount": [r"[$€£]\s?\d[\d,.]*(?:\s?(?:k|m|mm|bn|b)\b)?", r"\b\d[\d,.]*\s?(?:usd|dollars|eur|gbp)\b"],
    "path": [r"(?:/Users|/home|/private|/var/folders)/[^\s]+", r"~/[^\s]+"],
}
CREDENTIAL = re.compile("|".join(f"(?:{p})" for p in GENERIC["secret"][:-1]), re.I)


class GuardError(RuntimeError):
    pass


class Guard:
    def __init__(self, deny: str | Path | None = None, skip=()):
        classes = {k: list(v) for k, v in GENERIC.items()}
        allow: list[str] = []
        case_sensitive: set[str] = set()
        if deny:
            extra, hard, allow, case_sensitive = _load_deny(Path(deny))
            hard = [c for c in hard if c not in set(skip)]
            if not hard:
                raise GuardError("every deny class is skipped (fails open)")
            self.deny_classes = tuple(hard)
            for c in hard:
                classes[f"deny:{c}"] = list(extra[c])
                if c in case_sensitive:
                    case_sensitive = case_sensitive | {f"deny:{c}"}
        self.patterns = []
        for c, pats in classes.items():
            if not pats or not all(pats):
                raise GuardError(f"guard class {c!r} is empty (fails open)")
            flags = 0 if c in case_sensitive or c == "secret" else re.I
            self.patterns.append((c, re.compile("|".join(f"(?:{p})" for p in pats), flags)))
        self.allow = re.compile("|".join(f"(?:{p})" for p in allow), re.I) if allow else None
        self.deny_loaded = bool(deny)
        if not deny:
            self.deny_classes = ()

    def spans(self, s: str) -> list[tuple[int, int]]:
        t = s
        if self.allow:
            t = self.allow.sub(lambda m: "\0" * len(m.group(0)), s)
        out = []
        for _, rx in self.patterns:
            out += [m.span() for m in rx.finditer(t) if m.end() > m.start()]
        out.sort()
        merged: list[list[int]] = []
        for a, b in out:
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        return [(a, b) for a, b in merged]

    def _redact(self, s: str) -> tuple[str, bool]:
        hit = self.spans(s)
        for a, b in reversed(hit):
            s = s[:a] + REDACTED + s[b:]
        return s, bool(hit)

    def scrub(self, s, max_len: int = 160) -> tuple[str | None, bool]:
        """(clean text or None, redacted?). The FULL string is scrubbed first, then cut at a word boundary (a token cut
        in half is dropped, never kept as a fragment a pattern no longer recognises), then scanned again: any hit
        left means None."""
        if s is None:
            return None, False
        if not isinstance(s, str):
            return None, True
        try:
            s = re.sub(r"\s+", " ", s).strip()
            s, red = self._redact(s)
            if len(s) > max_len:
                cut = s[: max_len - 1]
                if not s[max_len - 1].isspace():
                    cut = cut.rsplit(" ", 1)[0] if " " in cut else ""
                s = (cut.rstrip() + "…") if cut.strip() else ""
            if self.spans(s.replace(REDACTED, " ")):
                return None, True
            return (s or None), red
        except Exception:  # noqa: BLE001 - a guard that cannot judge drops the value
            return None, True


def _load_deny(p: Path):
    """(classes, applied class names, allow, case-sensitive). Every class in the file is applied to ledger text
    except the ones the file lists as skipped (LEDGER_SKIP in a .py, "ledger_skip" in a .json): fail closed."""
    if not p.is_file():
        raise GuardError(f"deny file not found: {p}")
    try:
        if p.suffix == ".json":
            d = json.loads(p.read_text(encoding="utf-8"))
            deny, allow = d.get("classes") or {}, d.get("allow") or []
            skip, cs = set(d.get("ledger_skip") or []), set(d.get("case_sensitive") or [])
        else:
            spec = importlib.util.spec_from_file_location("ledger_deny", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            deny = getattr(mod, "DENY")
            skip = set(getattr(mod, "LEDGER_SKIP", ()) or ())
            allow = list(getattr(mod, "ALLOW", []) or [])
            cs = set(getattr(mod, "CASE_SENSITIVE", set()) or set())
    except GuardError:
        raise
    except Exception as e:  # noqa: BLE001
        raise GuardError(f"deny file {p} failed to load: {type(e).__name__}") from None
    if not isinstance(deny, dict) or not deny:
        raise GuardError(f"deny file {p} defines no classes")
    applied = [c for c in deny if c not in skip]
    missing = [c for c in applied if not deny.get(c) or not all(deny[c])]
    if missing or not applied:
        raise GuardError(f"deny file {p}: class(es) {missing or 'all'} empty")
    return deny, applied, allow, cs


def _strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for x in v.values():
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


def check_row(row: dict) -> None:
    for s in _strings(row):
        if CREDENTIAL.search(s):
            raise GuardError(f"credential-shaped string in ledger row {row.get('key')!r}; refusing to write")
