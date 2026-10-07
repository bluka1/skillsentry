# SkillSentry

Defensive tooling for third-party agent skills (the `SKILL.md` format). Two parts:

- **`skillsentry.py`** — static scanner. Reads skill packages and flags risky
  patterns, and crucially flags the **cross-skill chain** where one skill writes
  an "approval" record and another acts on it.
- **`guard.py`** — runtime reference guard. A deterministic gate in front of
  irreversible tool calls (delete / send / remote-exec / overwrite) that refuses
  to accept approval claims living in skill-produced files.

Built around the findings in *Chaining Skills to Hijack LLM Agents*
(Dong et al., 2026, arXiv:2610.01564). **Use it only to defend your own agents.**

## Why two layers

The attack in the paper does not live in any single file. An upstream skill does
real work and writes a progress record, slipping in one false line: *the user
approved the next step*. A downstream skill reads that record and acts on it.
Each skill looks fine read alone. Split that way, the attack succeeds ~5x more
often than the same intent in a single skill (84.3% vs 17.4% on GPT-5.4).

So:

1. **Static scan (`skillsentry.py`)** catches the obvious single-skill cases and
   the *structure* of a chain (a writer + a consumer + a dangerous action in the
   same installed set). It is the first layer and it is defeatable by rewording
   — treat a clean scan as "nothing obvious", not "safe".
2. **Runtime guard (`guard.py`)** is what actually holds. Approval is a fact
   about the user, so it can only come from the user's request — never from a
   file the agent wrote. The guard tags skill-produced files as untrusted and
   discards any approval claim that traces back to one.

## Install

No dependencies. Python 3.9+.

## Scanner usage

```bash
python skillsentry.py scan ./path/to/skills
python skillsentry.py scan ./skills --json report.json          # machine-readable
python skillsentry.py scan ./skills --rules my_rules.json       # extend/override rules
python skillsentry.py scan ./skills --fail-on HIGH              # CI gate (non-zero exit)
python skillsentry.py scan ./skills --trusted a,b               # a,b are first-party/pinned
python skillsentry.py scan ./skills --shared-workspace no       # skills do not share a dir
```

A "skill package" is any directory containing a `SKILL.md`. The scanner reads the
`SKILL.md` plus bundled `.py/.sh/.js/.ts/.json/.yaml` files.

### What it flags

| Category | Mechanism from the paper |
|---|---|
| `authority_promotion` | task progress reframed as permission ("approved for cleanup", "safe to delete") |
| `record_write` | tells the agent to persist a status/record file |
| `record_consume` | tells the agent to act on a recorded status |
| `dangerous_action` | delete / exfiltrate / remote-exec / overwrite source |
| `work_loop` | re-entry / repeat-forever (resource exhaustion) |
| `instruction_override` | override or hide from the user's original request |
| `obfuscation` | base64 / encoded blobs |

Per-skill scores map to CLEAN / LOW / MEDIUM / HIGH / CRITICAL.

### Cross-skill chain analysis (file-flow)

The real attack lives between skills. The chain analysis builds a small data-flow
graph: which skill **writes** which file, which skill **reads** it, and which
skills take a **state-changing action**. It flags any path where a file written
by one skill is read by a different skill before a destructive step.

- If the writer also frames progress as approval → **CRITICAL** (the paper's
  authority-promotion handoff).
- If no approval phrase but the file still flows into a state-changing step →
  **HIGH** (confirm the reader does not treat the file as permission).

This is why it beats a phrase-based rule. In `examples/reworded/`, the upstream
skill scans CLEAN and the downstream only LOW on per-skill rules — no approval
wording anywhere — yet the file-flow graph still raises the pair to HIGH because
`progress.state` flows into a delete.

### Scoping gate

Chain analysis only runs when it is worth it, following the decision rule:

> two or more **untrusted** skills, sharing a **workspace**, with at least one
> able to take a **state-changing action**.

Mark first-party/pinned skills with `--trusted name1,name2`, and set
`--shared-workspace no` when skills cannot hand files to each other. If the gate
is not met, the scanner says so and skips the chain pass — per-skill review is
enough.

### Extending rules

Pass `--rules extra.json` with a list of `{"id","category","weight","pattern"}`
objects. `pattern` is a Python regex, matched case-insensitively per line.

## Runtime guard usage

```bash
python guard.py        # runs the paper's "cleanup" scenario; guard refuses the delete
```

Wire `SkillGuard.authorize(action, target, claim_source_files=[...])` into your
tool dispatcher. Capture the user's real intent once in `OriginalRequest` and
never let a skill rewrite it. Snapshot the workspace before each skill
(`TaintLedger.snapshot`) and taint changes after (`mark_changes`). Any approval
that comes only from a tainted file is ignored; permission must come from the
original request, else the call is denied or escalated to a human.

## Limits (read these)

- **Per-skill phrase detection is best-effort and defeatable.** Any list of
  approval phrases has a rewording that walks past it. The file-flow chain pass
  mitigates this (it keys on the shared file, not the wording), but it too can be
  evaded if the filename is reworded or passed implicitly — then you get the
  lower-confidence "possible chain" note instead. A clean scan is never a
  guarantee.
- The chain pass matches files by **basename**. A handoff that never names the
  file in text (passes it through an env var, a tool return, etc.) will not be
  matched; the runtime guard is what covers that case.
- The guard is a reference pattern, not a drop-in for a specific framework.
- None of this estimates the paper's formal bounds; it operationalizes its
  mechanisms.

## When per-skill review is already enough

If every skill is first-party and pinned, or none can take an action with side
effects outside the workspace, a plain per-skill scan is fine. The chain risk
matters when three things are true at once: skills come from sources you don't
control, they share a working directory, and at least one can take a
state-changing action.

## References

- Dong et al., *Chaining Skills to Hijack LLM Agents*, arXiv:2610.01564 (2026)
- Debenedetti et al., *CaMeL* (provenance/capabilities for agents), arXiv:2503.18813 (2025)
