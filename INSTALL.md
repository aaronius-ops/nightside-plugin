# Installing the Nightside plugin

The plugin watches the shape of your work with Claude Code and grows a planet from it on https://nightside.world. It records counts, timings and tool names. It never records your prompts, your files, file or folder paths, commands, or what any tool returned. Nothing leaves your machine until you look at the exact bytes and confirm them.

These steps are for macOS and Linux. Allow about 10 minutes.

## 1. What you need

- **Claude Code**. Tested with Claude Code 2.1.296. If a /plugin command below is missing, update Claude Code first (`claude update`; `claude --version` shows yours).
- **python3**, version 3.9 or newer. Run `python3 --version`. The Python that ships with macOS is fine. Nothing to install with pip.
- **git**. Run `git --version`.
- Your Nightside sign-in: the berkeley.edu Google account, or the address you were invited with.

## 2. Install the plugin

Start Claude Code in any folder and type these two commands:

```
/plugin marketplace add aaronius-ops/nightside-plugin
/plugin install nightside@nightside
```

From a terminal, the same thing is `claude plugin marketplace add aaronius-ops/nightside-plugin` followed by `claude plugin install nightside@nightside`.

Quit Claude Code and start it again so the plugin's hooks load. From then on, capture is on in every project you open.

## 3. Get your plugin credential

1. Open https://nightside.world/reserve and sign in with Google, using the account above.
2. Reserve your planet if you have not already.
3. Open the **View** panel (top right; on a phone it is inside the View button). Click **Copy plugin credential**. A long string starting with `nsu2.` is copied to your clipboard. It is shown only once, so paste it in the next step right away.

The credential is a password for your planet. Do not paste it into a Claude chat, an email or a shared doc. It lasts 30 days, and you can revoke it in the same panel.

## 4. Connect the plugin to your planet

In a **terminal** (not inside Claude Code), run:

```
python3 "$(ls -d ~/.claude/plugins/cache/nightside/nightside/*/scripts/capture/planet.py | tail -1)" remote token
```

The command waits silently. Paste the credential and press Enter. It answers `Upload token saved (key ..., planet ...)` and `Manifests will be signed.` The credential is stored in `~/.nightside/capture/` with owner-only permissions and is never printed again.

Then, inside Claude Code:

```
/planet remote set https://nightside.world
```

`/planet remote show` tells you what is set. (If another plugin also has a `/planet` command, type `/nightside:planet` instead.)

## 5. Work as usual

Use Claude Code the way you normally do. In each project, the plugin's hooks write one small line per event to `~/.nightside/capture/` on your machine: the event type, the time, the tool's name (Bash, Read, Edit and so on), how long it took, whether it worked, and how many subagents ran. Names of your MCP servers and custom agents are replaced by codes. Each project (each git repository) becomes one island. Nothing from before you installed the plugin is imported.

The plugin also keeps a private copy of your Claude Code transcripts in `~/.nightside/agent-archive/` on your machine, so long builds can be audited later. That copy never leaves your computer. To turn it off, set `NIGHTSIDE_ARCHIVE=0` in your shell profile.

To pause capture, set `NIGHTSIDE_CAPTURE=0`.

## 6. Look before anything leaves

In the project you want on your planet, type:

```
/planet preview
```

The preview lists every project the plugin has captured on this machine. Each one shows its local name (your folder's name, shown only to you), its visibility (private or public), the public label that will place the island on the map, the byte count, a sha256 hash, and the exact text that would be sent. Pick the project for the folder you are in; `/planet status` marks it with `*`.

Every new project starts **private**. A private project shows up on your planet as an unnamed island. To make one public, so its island shows its public label, run `/planet privacy public` in that project and preview again. To change the label, run `/planet preview --label "a few plain words"`.

## 7. Upload

When the preview looks right, confirm that project by its hash:

```
/planet upload --confirm <sha256 from the preview>
```

Only those exact bytes are sent, and only to the server you set. Each project needs its own confirm. Nightside rebuilds planets every few minutes once your upload is accepted; the first build can take up to about 15 minutes.

## 8. Make a project private or take it back

- Private from now on: in that project, `/planet privacy private`, then preview and confirm again.
- Remove it from Nightside: `/planet withdraw` prints the project's id. Then `/planet withdraw --confirm <project id>` deletes everything you uploaded for that project and marks it private on your machine. The island is removed at the next rebuild.
- Disconnect completely: `/planet remote clear` removes the server address and your credential from this machine. Revoke the credential in the View panel too.

## Troubleshooting

- **"Your Nightside plugin is X; ... needs Y or newer."** Your plugin is out of date. In a terminal run `claude plugin marketplace update nightside` and then `claude plugin update nightside@nightside`, restart Claude Code, and preview again.
- **"UNSIGNED" in the preview, or "This upload is unsigned"**. The plugin has no signing key. Copy a fresh credential (step 3), run the `remote token` command again (step 4), then `/planet preview` and confirm the new hash.
- **"... is not accepting uploads yet"**. Nightside has not opened uploads yet. Your credential is fine and nothing was stored. Try again later.
- **"Not uploaded: the server did not accept it"**. Your credential expired or was revoked. Do steps 3 and 4 again, then preview and confirm.
- **"no saved preview has that hash"**. The project changed since you looked. Run `/planet preview` again and confirm the new hash.
- **The preview lists projects you did not mean to upload.** That is expected: it shows every project captured on this machine. Nothing is sent unless you confirm a hash, and you confirm one project at a time.
- **"Could not reach https://nightside.world"**. Check your connection and try again. Nothing was stored.
