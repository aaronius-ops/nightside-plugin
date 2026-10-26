"""The local public label: a short phrase (<= 40 characters) plus a category from the world
builder's vocabulary, made ON THIS MACHINE, shown in the consent preview, and approved or edited by the user before
anything leaves. The builder places the island from it. It exists because a default (metadata-tier) manifest has no
project name, and without one the classifier gets about 6 of 32 places right.

Where a label comes from (precedence: user > claude > heuristic):
  heuristic  deterministic, no network: label_for() below, from local signal only. The text is always one entry of
             PHRASES (a fixed table), so it cannot carry anything the session typed.
  claude     the opt-in rich summary (rich.py, triple opt-in, the user's own Claude Code) may propose one; model
             output is untrusted, so its text must use only VOCAB words, like any metadata-tier label.
  user       `/planet preview --label "..." --category ...`. At the metadata tier (every private project) the text
             must use only VOCAB words; at the rich tier (public projects that opted in) it is free text with the
             project_name rules. Either way it must pass the guard and must not mention a local name.

The signal (local only; none of it is in the manifest):
  kinds      the hook maps two things through CLOSED tables at write time and records only the resulting class:
             the suffix of a written file (EXT_KIND: ".wav" -> "ext-audio") and the program word of a Bash command
             (CMD_KIND: "ffmpeg" -> "cmd-media"). Never the path, the file or directory name, or the command line.
             Anything not in a table records nothing.
  tools      tool-name counts the surveyor already has; an MCP tool's own name part (after the hashed server) is
             matched against MCP_KIND keywords. Built-in agent types and the graph shape are read too.
Never derived from file or directory names, repo names, prompts, tool inputs or outputs.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

VOCAB_PATH = Path(__file__).resolve().parent / "label_vocab.json"
SOURCES = ("heuristic", "claude", "user")
MAX_LEN = 40
TEXT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 &+-]{0,39}$")   # no . / \ : @ _ ' " (paths, files, ids, mail)
WORD_SPLIT = re.compile(r"[ &+-]+")
NUMBER_RUN = re.compile(r"\d{3,}")                               # years, amounts, phone fragments


@lru_cache(maxsize=1)
def _vocab() -> dict:
    return json.loads(VOCAB_PATH.read_text(encoding="utf-8"))


def categories() -> list[str]:
    return list(_vocab()["categories"])


@lru_cache(maxsize=1)
def words() -> frozenset[str]:
    return frozenset(w.lower() for w in _vocab()["words"])


def text_words(text: str) -> list[str]:
    return [w for w in WORD_SPLIT.split(text.lower()) if w]


def unknown_words(text: str) -> list[str]:
    return [w for w in text_words(text) if w not in words()]


# ------------------------------------------------------------------------------- closed signal tables ---
KINDS = ("ext-audio", "ext-video", "ext-image", "ext-3d", "ext-web", "ext-code", "ext-data", "ext-docs",
         "ext-config", "cmd-media", "cmd-image", "cmd-3d", "cmd-web", "cmd-py", "cmd-data", "cmd-docs", "cmd-test",
         "cmd-infra", "cmd-schedule")
_EXT = {
    "ext-audio": "wav mp3 flac ogg m4a aac aiff opus",
    "ext-video": "mp4 mov webm mkv avi m4v",
    "ext-image": "png jpg jpeg webp gif svg psd exr tif tiff heic avif",
    "ext-3d": "blend glb gltf fbx obj usd usda usdz stl ply unity prefab uasset",
    "ext-web": "html htm css scss tsx jsx vue svelte astro",
    "ext-code": "py js ts mjs cjs go rs java rb swift kt c cc cpp h hpp cs sh zsh lua php scala",
    "ext-data": "csv tsv parquet ipynb sql xlsx xls jsonl feather arrow duckdb sqlite",
    "ext-docs": "md mdx txt rst docx doc tex pdf odt rtf pptx key",
    "ext-config": "yaml yml toml ini tf hcl cfg conf env",
}
EXT_KIND = {"." + e: k for k, es in _EXT.items() for e in es.split()}
_CMD = {
    "cmd-media": "ffmpeg ffprobe sox whisper yt-dlp",
    "cmd-image": "magick convert exiftool",
    "cmd-3d": "blender unity",
    "cmd-web": "npm pnpm yarn bun node next vite deno",
    "cmd-py": "python python3 pip pip3 uv poetry",
    "cmd-data": "jupyter duckdb sqlite3 psql bq mysql dbt",
    "cmd-docs": "pandoc latexmk pdflatex xelatex",
    "cmd-test": "pytest jest vitest playwright tox mocha",
    "cmd-infra": "docker kubectl terraform helm firebase vercel flyctl pulumi aws az make bazel",
    "cmd-schedule": "crontab launchctl systemctl",
}
CMD_KIND = {c: k for k, cs in _CMD.items() for c in cs.split()}
_PREFIX = {"sudo", "env", "time", "nohup", "exec", "npx", "uvx", "command", "then", "do"}
_RUNNER = {"run", "exec"}  # uv run X, poetry run X, npm exec X
MCP_KIND = (  # an MCP tool's own name part -> a coarse kind (keywords; the part never leaves at the metadata tier)
    (re.compile(r"(?i)speech|tts|voice|audio|transcri|sound|music"), "mcp-audio"),
    (re.compile(r"(?i)video|clip|veo"), "mcp-video"),
    (re.compile(r"(?i)image|photo|picture|draw|paint"), "mcp-image"),
    (re.compile(r"(?i)calendar|event|schedule|remind"), "mcp-schedule"),
    (re.compile(r"(?i)mail|draft|message|slack|send|thread|inbox"), "mcp-mail"),
    (re.compile(r"(?i)invoice|ledger|payment|bank|account|expense|xero|stripe"), "mcp-finance"),
    (re.compile(r"(?i)sheet|spreadsheet|query|table|dataset"), "mcp-data"),
    (re.compile(r"(?i)doc|page|wiki|note|brain"), "mcp-docs"),
    (re.compile(r"(?i)search|fetch|browse|crawl|navigate|read_page"), "mcp-research"),
    (re.compile(r"(?i)deploy|build|release|pipeline|cluster|instance"), "mcp-infra"),
)


def ext_kind(path) -> str | None:
    """The class of a written file's suffix, from EXT_KIND only (the name itself is never kept)."""
    if not isinstance(path, str) or not path or len(path) > 4096:
        return None
    return EXT_KIND.get(os.path.splitext(path)[1].lower())


def cmd_kind(command) -> str | None:
    """The class of a Bash command's program word, from CMD_KIND only (the command line is never kept)."""
    if not isinstance(command, str) or not command:
        return None
    toks = command[:512].replace(";", " ").replace("&&", " ").replace("|", " ").split()
    i = 0
    while i < len(toks) and i < 8:
        t = toks[i]
        if "=" in t.split("/")[0] or t in _PREFIX:
            i += 1
            continue
        prog = re.sub(r"\d+(?:\.\d+)*$", "", t.rsplit("/", 1)[-1].lower())  # python3.12 -> python
        if prog in ("uv", "poetry") and i + 1 < len(toks) and toks[i + 1] in _RUNNER:
            i += 2  # uv run X: X is the program
            continue
        if prog in ("python", "python3") and i + 2 < len(toks) and toks[i + 1] == "-m":
            return CMD_KIND.get(toks[i + 2].lower(), "cmd-py")
        k = CMD_KIND.get(prog) or CMD_KIND.get(t.rsplit("/", 1)[-1].lower())
        return k
    return None


def event_kind(tool, tool_input) -> str | None:
    """What the hook may record for one tool call: a KINDS value or None. Only these two fields are looked at."""
    if not isinstance(tool_input, dict):
        return None
    if tool in ("Write", "Edit", "MultiEdit"):
        return ext_kind(tool_input.get("file_path"))
    if tool == "NotebookEdit":
        return "ext-data"
    if tool == "Bash":
        return cmd_kind(tool_input.get("command"))
    return None


def tool_kinds(tools: dict) -> Counter:
    out: Counter = Counter()
    for name, n in (tools or {}).items():
        if not isinstance(n, int):
            continue
        if name.startswith("Web"):  # the built-in web search and page-read tools
            out["mcp-research"] += n
        m = re.match(r"^mcp__[0-9a-f]{8}__(.+)$", name)
        if m:
            for rx, k in MCP_KIND:
                if rx.search(m.group(1)):
                    out[k] += n
                    break
    return out


# ---------------------------------------------------------------------------------------- heuristics ---
PHRASES = {  # category -> {flavour: text}; "" is the category's default text (also used for --category alone)
    "media-pipeline": {"audio": "Voice and audio pipeline", "image": "Image generation pipeline",
                       "video": "Video production pipeline", "": "Media production pipeline"},
    "world-simulation": {"": "3D world and simulation build"},
    "knowledge-research": {"data": "Data analysis workbench", "research": "Research and notes",
                           "": "Knowledge and research work"},
    "writing-drafting": {"": "Document drafting workflow"},
    "build-deploy-infra": {"web": "Web app build and deploy", "": "Build and deploy tooling"},
    "harness-testing": {"": "Test harness and checks"},
    "cron-daemon": {"": "Scheduled agent workflow"},
    "outreach-sales": {"": "Outreach and messaging"},
    "finance-bookkeeping": {"": "Bookkeeping and finance"},
    "legal-governance": {"": "Legal and governance work"},
    "eval-hillclimb": {"": "Evaluation and tuning loop"},
    "personal-family": {"": "Personal assistant"},
    "unclassified": {"web": "Web app build", "code": "Coding workflow", "": "Agentic workflow"},
}
HEURISTIC_TEXTS = frozenset(t for d in PHRASES.values() for t in d.values())
MIN_EVIDENCE = 2


def default_text(category: str) -> str:
    return PHRASES.get(category, PHRASES["unclassified"])[""]


def _scores(k: Counter) -> dict[str, tuple[float, str]]:
    audio, video, image = k["ext-audio"] + k["mcp-audio"], k["ext-video"] + k["mcp-video"], \
        k["ext-image"] + k["cmd-image"] + k["mcp-image"]
    media = audio + video + image + k["cmd-media"]
    flav = max((("audio", audio + k["cmd-media"] * (audio >= video)), ("video", video), ("image", image)),
               key=lambda x: x[1])[0] if media else ""
    data = k["ext-data"] + k["cmd-data"] + k["mcp-data"]
    research = k["mcp-research"]
    code = k["ext-code"] + k["cmd-py"]
    docs = k["ext-docs"] + k["cmd-docs"] + k["mcp-docs"]
    web = k["ext-web"] + k["cmd-web"]
    infra = k["cmd-infra"] + k["mcp-infra"] + 0.5 * k["ext-config"]
    return {
        "media-pipeline": (media, flav),
        "world-simulation": (k["ext-3d"] + k["cmd-3d"], ""),
        "knowledge-research": (max(data, research), "data" if data >= research else "research"),
        # prose beats code only when it dominates (every code project writes a README)
        "writing-drafting": (docs if docs > code + web else 0.3 * docs, ""),
        "build-deploy-infra": (infra + (web if infra >= MIN_EVIDENCE else 0), "web" if web > infra else ""),
        "harness-testing": (k["cmd-test"], ""),
        "cron-daemon": (k["cmd-schedule"] + k["mcp-schedule"], ""),
        "outreach-sales": (k["mcp-mail"], ""),
        "finance-bookkeeping": (k["mcp-finance"], ""),
    }


ORDER = ("media-pipeline", "world-simulation", "finance-bookkeeping", "outreach-sales", "cron-daemon",
         "harness-testing", "knowledge-research", "writing-drafting", "build-deploy-infra")


def heuristic(kinds: Counter, tools: dict) -> dict:
    """{"text", "category", "source": "heuristic"} from local signal only. Deterministic; ties go by ORDER."""
    k = Counter(kinds) + tool_kinds(tools)
    sc = _scores(k)
    best = max(ORDER, key=lambda c: (sc[c][0], -ORDER.index(c)))
    if sc[best][0] >= MIN_EVIDENCE:
        cat, flav = best, sc[best][1]
    else:
        cat = "unclassified"
        web, code = k["ext-web"] + k["cmd-web"], k["ext-code"] + k["cmd-py"]
        flav = "web" if web >= MIN_EVIDENCE and web >= code else "code" if code >= MIN_EVIDENCE else ""
    text = PHRASES[cat].get(flav) or PHRASES[cat][""]
    return {"text": text, "category": cat, "source": "heuristic"}


def candidates(kinds: Counter, tools: dict) -> list[dict]:
    """The heuristic label, then its category's default text, then the generic one (for the local-name check)."""
    h = heuristic(kinds, tools)
    out = [h, dict(h, text=default_text(h["category"])), {"text": default_text("unclassified"),
                                                           "category": "unclassified", "source": "heuristic"}]
    seen, uniq = set(), []
    for c in out:
        if (c["text"], c["category"]) not in seen:
            seen.add((c["text"], c["category"]))
            uniq.append(c)
    return uniq


# ------------------------------------------------------------------------------------ local names ---
def _norm(s: str) -> str:
    return " ".join(re.split(r"[^a-z0-9]+", s.lower())).strip()


def local_names(root: Path | None, pid: str | None, extra=()) -> set[str]:
    """Names this machine knows and a label must not repeat: the repo slug, raw MCP server and custom agent names
    (names.json), the login name and the home directory's name, plus `extra` (e.g. the project dir). Local only."""
    out: set[str] = set()
    vals = list(extra)
    try:
        import getpass
        vals.append(getpass.getuser())
    except Exception:  # noqa: BLE001
        pass
    vals.append(Path.home().name)
    if root is not None:
        from capture import common as C
        if pid:
            vals.append(str((C.read_index(root).get(pid) or {}).get("name") or ""))
        vals += [str(v) for v in C.read_names(root).values()]
    for v in vals:
        n = _norm(str(v))
        if len(n) >= 3:
            out.add(n)
    return out


SENTENCE_KEEP = {"3d": "3D", "2d": "2D", "ai": "AI", "api": "API", "ci": "CI", "qa": "QA", "cli": "CLI", "sdk": "SDK",
                 "etl": "ETL", "crm": "CRM"}


def normalise(text: str) -> str:
    """Sentence case, repeated words dropped (for a model's proposal): 'Voice VOICE Audio pipeline' ->
    'Voice audio pipeline'. Acronyms in SENTENCE_KEEP keep their capitals."""
    seen, out = set(), []
    for w in text.split():
        lw = w.lower()
        if lw in seen:
            continue
        seen.add(lw)
        out.append(SENTENCE_KEEP.get(lw, lw))
    s = " ".join(out)
    return s[:1].upper() + s[1:] if s else s


def mentions_local_name(text: str, names: set[str]) -> bool:
    """True when the label repeats a local name: a whole name as a phrase, or any of its words (>= 3 characters)
    that is not a generic VOCAB word."""
    t = " " + _norm(text) + " "
    tw = set(t.split())
    flat = t.replace(" ", "")  # separator-free, case-folded: "Acmecorp" vs acme-corp, "Dock 12" vs dock12
    for n in names:
        if " " + n + " " in t:
            return True
        nf = n.replace(" ", "")
        if len(nf) >= 4 and nf in flat:
            return True
        if any(len(w) >= 3 and w not in words() and w in tw for w in n.split()):
            return True
    return False
