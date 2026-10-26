---
description: Your Nightside planet from this machine's local capture - name, privacy (rich|metadata, public|private), status, preview (with each project's public label), upload of confirmed bytes, withdraw, remote (server and credential).
argument-hint: name <Name> | privacy rich|metadata|public|private [--here|--default] [--name <project name>] [--summary|--no-summary] | status [--survey] [--rich] | preview [--label "<text>"] [--category <category>] | upload [--confirm <sha256>] | withdraw [--confirm <project id>] | remote show|set <base URL>|clear
---

# /planet

Arguments: `$ARGUMENTS`.

1. **Find the script.** `PLANET="${CLAUDE_PLUGIN_ROOT}/scripts/capture/planet.py"`. If that path does not exist, use `ls -d ~/.claude/plugins/cache/*/nightside/*/scripts/capture/planet.py | tail -1`. Stop if neither exists.

2. **Run it** from the project root with the user's arguments, each one as a separate quoted word (never paste the arguments into the shell unquoted): `python3 "$PLANET" <subcommand> [options]`. With no arguments, run `status`.

3. **Show the output verbatim** in a code block. Do not summarize `preview` output: the user must see the exact bytes.

4. **The public label.** Every project in the preview has a `PUBLIC LABEL` line: a short phrase (at most 40 characters) and a category, made on this machine from what kinds of files were written and which programs ran (classes only; never a file, folder, repo or command name), or proposed by the opt-in rich summary. The map places the project's island from it. Point the user at it before asking for a yes. To change it, run `python3 "$PLANET" preview --label "<text>" --category <category>` (either flag alone works; `--label auto` goes back to the generated one). For a private project (the metadata tier) the text may use only generic words from `scripts/capture/label_vocab.json`; a public rich-tier project may use free text. A label with a path, file name, address, number, secret or a local name (the repo, a tool server, an agent, the login) is refused, and the reason is printed. Show any refusal verbatim. Never suggest a label that names the project, a person, a company or a place.

5. **`upload`** (the consent step). Run `python3 "$PLANET" preview` first and show it verbatim. The preview lists every project captured on this machine, each with its local name (the repository's folder name, shown only to the user and never sent); `/planet status` marks the current directory's project with `*`. The preview saves exactly the bytes it printed and says where a yes would send them (or that upload is not enabled). Then ask the user, for each project the preview lists, whether to send exactly those bytes (y/n). Only on an explicit yes for a project, run `python3 "$PLANET" upload --confirm <that project's sha256>`; confirm checks the SAVED bytes (it never re-surveys), so work done after the preview does not change what was approved. If confirm says no saved preview has that hash, show a fresh preview and ask again. A project name leaves only if the user chose one with `--name`. Without a configured server the script answers that upload is not enabled and nothing was sent; say so plainly.

6. **`withdraw`** takes a project back. `python3 "$PLANET" withdraw` (no flag) only prints this directory's project id and what would happen. Only on the user's explicit yes, run `python3 "$PLANET" withdraw --confirm <project id>`: the server deletes every manifest of that project the user uploaded, and the project is set private on this machine. Show the answer verbatim.

**No back-fill.** A planet grows only from what this plugin captures from now on: each project you work in with the plugin installed becomes one island. Past sessions, repositories and transcripts are never imported, and `planet.py backfill` / `planet.py import` only print that. Do not offer a workaround.

7. **`remote`.** `remote show`, `remote set <base URL>` (`https://nightside.world`, or the domain the planet's owner gives; never a `*.run.app` host) and `remote clear` are local config. The upload credential is a secret: never ask the user to paste it into this chat and never run `remote token` yourself; tell the user to run `python3 <path to planet.py> remote token` in their own terminal and paste the credential there (or use `--file <file>`).

Rules: only `upload --confirm` and `withdraw --confirm` with a configured server open a connection, and upload sends only the confirmed bytes. Never use a network tool, never copy spool, outbox, token or transcript files anywhere, and never print the capture key, the token or the spool's raw lines. `invite` and `open` print that they are not in the plugin yet. To turn capture off: `NIGHTSIDE_CAPTURE=0` in the environment, or `"enabled": false` in `~/.config/nightside/capture.json`.
