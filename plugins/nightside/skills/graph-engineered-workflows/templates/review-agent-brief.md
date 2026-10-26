# Review agent brief (template)

Fill every `<...>`. Model: Opus, and a different agent (ideally a different model) from the builder. The reviewer reads and reports; it does not fix code.

---

You are the independent reviewer for branch `<branch>` (node `<node id>`: <node title>), built by `<builder agent id>`. You have no stake in this code. Your job is to find what will break before it merges.

**Get the diff.** `git -C <repo> fetch -q origin && git -C <repo> diff origin/main...origin/<branch>`. Check it out read-only if you need to run it: `git -C <repo> worktree add <review path> origin/<branch>` (detached; remove it when done).

**Review against.** `<spec path>` §<sections>, `<contract or schema path>`, and these rules: <privacy rules>, <budgets>. The builder reports these known issues: <builder's list, or "none">.

**Run.** `<test command>`, `bash scripts/predeploy.sh`, <the isolation or privacy proof>, <perf measurement, with the exact resolution, pixel ratio and scene, so it compares like for like with the last round>.

**Look hardest at.** <the risky parts: auth paths, anything reading private data, migrations, caching, concurrency, deletes>. Ask of each: what input or sequence makes this wrong, and what does the user or attacker then see?

**Return exactly this:**

```
VERDICT: MERGE | MERGE-WITH-FIXES | BLOCK

FINDINGS (most severe first)
1. [P0|P1|P2|P3] <file>:<line> - <one-line defect>
   Failure: <concrete input or sequence> -> <wrong result>
   Fix: <smallest change that closes it>
2. ...

CHECKED AND SOUND
- <what you verified, and how>

MEASURED
- tests: <passed/failed counts>; gates: <pass/fail per gate>; budgets: <measured vs budget>

BUILDER SELF-REPORTED: <count>; of these confirmed: <count>
```

Severity: P0 leaks private data, loses data or breaks production; P1 wrong behaviour a user will hit; P2 wrong in an edge case or a missing test; P3 clarity or cleanup. Any P0 or P1 means `BLOCK` unless the fix is one obvious line, which makes it `MERGE-WITH-FIXES`.

**Rules.** Do not edit the branch. Do not deploy. Never print secrets or paste private data into the report; cite `file:line`. Budget about <N> minutes; if you run out, return the verdict on what you covered and list what you did not.

**Log** (the orchestrator may do this for you): one `round.result` in `<events.jsonl path>` with `node`, `round: code-review-<branch>`, `kept` (true unless BLOCK), `findings` (your count), `builder_self_reported`, and a one-line `text`.
