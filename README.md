# Nightside plugin for Claude Code

Nightside turns the shape of your agentic work into a planet: each project you build with Claude Code becomes an island on https://nightside.world. This repository is the Claude Code plugin marketplace for it.

The plugin records counts, timings and tool names from Claude Code's hooks. It never records prompts, files, paths, commands or tool output. It shows you the exact bytes before anything leaves, and it uploads a project only when you confirm that project's sha256.

Install:

```
/plugin marketplace add aaronius-ops/nightside-plugin
/plugin install nightside@nightside
```

Then follow [INSTALL.md](INSTALL.md) to connect your planet. How capture, consent, signing and the privacy checks work is in [plugins/nightside/README.md](plugins/nightside/README.md).

Requirements: Claude Code, `python3` 3.9 or newer, git. No other dependencies.
