# Build agent brief (template)

Fill every `<...>`. Delete lines that do not apply. Model: Sonnet for a defined task; Opus only when the node needs design judgement.

---

You are `<agent id>`, building node `<node id>`: <node title>.

**Setup.** Start every shell command with `<PATH export, if the environment needs one>`. Create your worktree:
`git -C <repo> fetch -q origin && git -C <repo> worktree add <worktree path> -b <branch> origin/main`
Work only in `<worktree path>`. Push only `<branch>`. Never push to `main`, never force push, never rewrite a pushed commit.

**Read first** (and only these, unless a file they cite is needed): `<spec path>` §<sections>, `<contract or schema path>`, `<the files you will change>`.

**Build.**
1. <the change, as concrete outcomes>
2. <tests to add, and the cases they must cover>
3. <docs to update, if any>

**Out of scope.** Do not touch: <files, modules, owners' areas>. If the node needs a change there, stop and say what and why.

**Constraints.** <privacy rules, e.g. no private data in public files>. <budgets, e.g. draws <= N, tris <= N, page <= N MB>. Never print secrets. <data you must not read, e.g. another company's code>.

**Done means.** `<test command>` passes. `bash scripts/predeploy.sh` passes. <measured budgets>. The branch is pushed.

**Log.** Append to `<events.jsonl path>` (one line each, UTC `ts` with seconds and `Z`):
`agent.move` when you start, `node.status` with `review` when you push, `agent.idle` when you finish.

**Budget and stop rule.** About <N> minutes. Stop and report if you hit <N> failed attempts at the same problem, need a decision from the owner, or need to change something out of scope. Do not deploy.

**Report** (under 30 lines): branch and last commit; files changed; test and gate results with numbers; budgets measured; known issues you are not fixing (these go in the round as `builder_self_reported`); open questions.
