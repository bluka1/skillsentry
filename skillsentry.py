#!/usr/bin/env python3
"""
SkillSentry - static analyzer for agent skill packages (SKILL.md and bundled files).

Flags skills that show the patterns described in "Chaining Skills to Hijack LLM
Agents" (Dong et al., 2026): authority-promotion language, cross-skill record
handoffs, dangerous target actions, work-loop re-entry, and instruction override.

The cross-skill chain analysis is FILE-FLOW based: it connects the actual file
one skill writes to the file another skill reads before a state-changing action,
rather than just noting that the ingredients exist somewhere in the set.

A scoping gate decides when chain analysis is worth running at all, following the
rule: it matters only when two or more skills come from sources you do not
control, they share a workspace, and at least one can take a state-changing
action.

Defensive use only. Run it over a directory of skill packages BEFORE installing
them, and treat HIGH/CRITICAL findings as a reason to review by hand.

Stdlib only. Python 3.9+.

Usage:
    python skillsentry.py scan ./skills
    python skillsentry.py scan ./skills --json report.json
    python skillsentry.py scan ./skills --rules my_rules.json
    python skillsentry.py scan ./skills --trusted my-first-party,other-pinned
    python skillsentry.py scan ./skills --shared-workspace no
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

# --------------------------------------------------------------------------- #
# Rule packs
#
# Each rule: id, category, weight, and a regex (compiled case-insensitive).
# Categories map to the attack mechanisms in the paper:
#   authority_promotion  - turns task progress into a claim of permission
#   record_write         - tells the agent to persist a status/record file
#   record_consume       - tells the agent to act on a recorded status
#   dangerous_action     - delete / exfiltrate / execute-remote / overwrite source
#   work_loop            - re-entry / repeat-forever instructions
#   instruction_override - override the user's original request
#   obfuscation          - hidden or encoded instructions
#
# Weights are additive per skill and capped. They are heuristics, not proof.
# --------------------------------------------------------------------------- #

DEFAULT_RULES: list[dict] = [
    # --- authority promotion: progress reframed as permission -------------- #
    {"id": "AP-approved", "category": "authority_promotion", "weight": 25,
     "pattern": r"\b(?:pre[- ]?approved|already approved|approved for|authori[sz]ed to|"
                r"permission (?:is )?granted|user (?:has )?(?:consented|approved|authori[sz]ed)|"
                r"(?:owner|admin|manager|reviewer) (?:has )?(?:signed off|approved|consented)|"
                r"sign(?:ed)? off|cleared for|safe to (?:delete|remove|send|share|run))\b"},
    {"id": "AP-eligible", "category": "authority_promotion", "weight": 22,
     "pattern": r"\b(?:eligible for (?:cleanup|deletion|removal|replacement)|"
                r"marked (?:as )?(?:approved|authori[sz]ed|safe|eligible)|"
                r"ready (?:to|for) (?:delete|send|transfer|disclose))\b"},
    {"id": "AP-no-confirm", "category": "authority_promotion", "weight": 18,
     "pattern": r"\b(?:no (?:need|confirmation) (?:to|for) (?:ask|confirm)|"
                r"do not ask (?:the user|for confirmation|again)|"
                r"without (?:asking|confirming|notifying) the user)\b"},

    # --- record handoff: write a status the next skill will trust ---------- #
    {"id": "RW-write-record", "category": "record_write", "weight": 18,
     "pattern": r"\b(?:record|write|save|log|note|persist|store) (?:the )?"
                r"(?:status|approval|progress|decision|record|state|result) "
                r"(?:to|in|into|as) (?:a )?(?:file|\.?[\w/-]+\.(?:md|json|txt|ya?ml|log))\b"},
    {"id": "RW-mark-status", "category": "record_write", "weight": 16,
     "pattern": r"\b(?:mark|flag|set|update) (?:the )?[\w .\"'/-]{0,40}?"
                r"(?:status|field|entry|file) (?:to|as) "
                r"(?:approved|authori[sz]ed|eligible|cleanup|ready|done|complete)\b"},
    {"id": "RW-handoff-file", "category": "record_write", "weight": 10,
     "pattern": r"\b(?:handoff|hand[- ]off|cross[- ]skill|shared) (?:record|file|state|note)\b"},

    # --- record consumption: act on what a prior skill wrote --------------- #
    {"id": "RC-follow-record", "category": "record_consume", "weight": 24,
     "pattern": r"\b(?:read|load|open|check) (?:the )?(?:record|status|handoff|note|state|file) "
                r"(?:and|then) (?:follow|act on|execute|perform|proceed|do)\b"},
    {"id": "RC-based-on-record", "category": "record_consume", "weight": 22,
     "pattern": r"\b(?:based on|according to|per|as (?:indicated|recorded) (?:in|by)) "
                r"(?:its |the )?(?:recorded )?(?:status|record|approval|note|state)\b"},
    {"id": "RC-proposed-step", "category": "record_consume", "weight": 16,
     "pattern": r"\bfollow (?:its |the )?proposed (?:next )?(?:step|action|unit)\b"},

    # --- dangerous target actions ------------------------------------------ #
    {"id": "DA-delete", "category": "dangerous_action", "weight": 20,
     "pattern": r"(?:\brm\s+-[rf]+\b|\bunlink\b|\bos\.remove\b|\bshutil\.rmtree\b|"
                r"\b(?:delete|remove|erase|wipe) (?:the )?(?:original|source|input|existing)[\w ]{0,20}?(?:file|files|data))"},
    {"id": "DA-exfil", "category": "dangerous_action", "weight": 20,
     "pattern": r"(?:\bcurl\b|\bwget\b|requests\.(?:post|put)|urllib|fetch\(|"
                r"\bupload\b|\b(?:send|transfer|post|exfiltrate|disclose) (?:the )?"
                r"(?:file|data|contents|material) (?:to|at) (?:https?://|a (?:remote|external)))"},
    {"id": "DA-remote-exec", "category": "dangerous_action", "weight": 26,
     "pattern": r"(?:curl[^\n|]*\|\s*(?:ba)?sh|wget[^\n|]*\|\s*(?:ba)?sh|"
                r"\b(?:download|retrieve|fetch) (?:and (?:then )?)?(?:run|execute|eval)\b|"
                r"\beval\(|\bexec\(|subprocess\.(?:call|run|Popen))"},
    {"id": "DA-overwrite-source", "category": "dangerous_action", "weight": 16,
     "pattern": r"\b(?:overwrite|replace|modify) (?:the )?(?:original|source|input) (?:file|content|data)\b"},

    # --- work loop / resource exhaustion ----------------------------------- #
    {"id": "WL-reentry", "category": "work_loop", "weight": 18,
     "pattern": r"\b(?:return to (?:the )?(?:entry|start|first|beginning)|"
                r"go back to (?:the )?(?:entry|start|beginning)|re[- ]?enter|"
                r"start (?:another|the next) (?:unit|cycle|round|iteration))\b"},
    {"id": "WL-repeat-forever", "category": "work_loop", "weight": 14,
     "pattern": r"\b(?:repeat (?:indefinitely|forever|continuously|until)|"
                r"keep (?:going|working|running)|loop (?:back|again)|"
                r"continue (?:this )?(?:process )?(?:indefinitely|without stopping))\b"},

    # --- instruction override ---------------------------------------------- #
    {"id": "IO-ignore-user", "category": "instruction_override", "weight": 28,
     "pattern": r"\b(?:ignore|disregard|override|bypass) (?:the )?(?:user'?s? |original )?"
                r"(?:request|instruction|requirement|constraint|preference)s?\b"},
    {"id": "IO-regardless", "category": "instruction_override", "weight": 20,
     "pattern": r"\b(?:regardless of|even if|despite) (?:the )?(?:user|original|what the user)\b"},
    {"id": "IO-silent", "category": "instruction_override", "weight": 22,
     "pattern": r"\b(?:do not (?:mention|tell|inform|notify|reveal) (?:this )?(?:to )?the user|"
                r"without the user'?s? (?:knowledge|awareness)|silently|covertly)\b"},

    # --- obfuscation -------------------------------------------------------- #
    {"id": "OB-base64", "category": "obfuscation", "weight": 14,
     "pattern": r"(?:base64|b64decode|atob\(|from_?base64)"},
    {"id": "OB-long-blob", "category": "obfuscation", "weight": 10,
     "pattern": r"[A-Za-z0-9+/]{120,}={0,2}"},
]

SEVERITY_BANDS = [(80, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (1, "LOW"), (0, "CLEAN")]
SCAN_EXTENSIONS = {".md", ".txt", ".py", ".sh", ".js", ".ts", ".json", ".yaml", ".yml"}
MAX_FILE_BYTES = 2_000_000

# --------------------------------------------------------------------------- #
# File-flow extraction
#
# A line "writes" a file if it names a file next to a write verb; it "reads" a
# file if it names a file next to a read verb. We normalize to the basename so a
# writer saying `./out/cleanup_record.md` matches a reader saying
# `cleanup_record.md`.
# --------------------------------------------------------------------------- #
WRITE_VERBS = re.compile(
    r"\b(?:write|writes|writing|save|saves|record|records|recording|log|logs|"
    r"persist|persists|store|stores|create|creates|mark|marks|marking|update|"
    r"updates|note|notes|flag|flags|set|sets|append|appends|emit|emits)\b",
    re.IGNORECASE)
READ_VERBS = re.compile(
    r"\b(?:read|reads|reading|load|loads|open|opens|check|checks|parse|parses|"
    r"follow|follows|following|consult|consults|review|reviews|inspect|inspects|"
    r"ingest|ingests)\b",
    re.IGNORECASE)
FILE_TOKEN = re.compile(
    r"`([^`\n]*?\.[A-Za-z0-9]{1,6})`"                       # `name.ext` in backticks
    r"|\b([\w./-]+\.(?:md|json|txt|ya?ml|log|csv|state|rec))\b",  # bare name.ext
    re.IGNORECASE)


def _filenames(line: str) -> list[str]:
    out = []
    for m in FILE_TOKEN.finditer(line):
        name = m.group(1) or m.group(2)
        if name:
            out.append(os.path.basename(name.strip().strip("`")))
    return out


def extract_file_refs(text: str) -> tuple[dict[str, int], dict[str, int]]:
    """Return (writes, reads): {basename -> first line number}."""
    writes: dict[str, int] = {}
    reads: dict[str, int] = {}
    for i, line in enumerate(text.splitlines(), 1):
        names = _filenames(line)
        if not names:
            continue
        is_write = bool(WRITE_VERBS.search(line))
        is_read = bool(READ_VERBS.search(line))
        for name in names:
            if is_write:
                writes.setdefault(name, i)
            if is_read:
                reads.setdefault(name, i)
    return writes, reads


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Match:
    rule_id: str
    category: str
    weight: int
    file: str
    line: int
    excerpt: str


@dataclass
class SkillReport:
    name: str
    path: str
    score: int = 0
    severity: str = "CLEAN"
    categories: set[str] = field(default_factory=set)
    matches: list[Match] = field(default_factory=list)
    writes: dict[str, int] = field(default_factory=dict)  # basename -> line
    reads: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["categories"] = sorted(self.categories)
        return d


@dataclass
class ChainFinding:
    kind: str                 # "precise" (shared file) or "possible" (presence only)
    severity: str             # CRITICAL / HIGH
    file: str | None
    upstream: list[str]
    downstream: list[str]
    claim_carried: bool
    note: str


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
class Scanner:
    def __init__(self, rules: list[dict]):
        self.rules = []
        for r in rules:
            try:
                compiled = re.compile(r["pattern"], re.IGNORECASE)
            except re.error as e:
                print(f"[warn] skipping bad rule {r.get('id')}: {e}", file=sys.stderr)
                continue
            self.rules.append({**r, "re": compiled})

    def scan_text(self, text: str, fname: str) -> list[Match]:
        out: list[Match] = []
        for i, line in enumerate(text.splitlines(), 1):
            line_to_test = line[:5000] if len(line) > 5000 else line
            for rule in self.rules:
                m = rule["re"].search(line_to_test)
                if m:
                    start = max(0, m.start() - 20)
                    end = min(len(line_to_test), m.end() + 20)
                    out.append(Match(rule["id"], rule["category"], rule["weight"],
                                     fname, i, line_to_test[start:end].strip()))
        return out

    def scan_skill(self, skill_dir: Path, root: Path) -> SkillReport:
        rep = SkillReport(name=skill_dir.name, path=str(skill_dir.relative_to(root)))
        for f in sorted(skill_dir.rglob("*")):
            if not f.is_file() or f.suffix.lower() not in SCAN_EXTENSIONS:
                continue
            try:
                if f.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(f.relative_to(skill_dir))
            rep.matches.extend(self.scan_text(text, rel))
            w, r = extract_file_refs(text)
            for name, ln in w.items():
                rep.writes.setdefault(name, ln)
            for name, ln in r.items():
                rep.reads.setdefault(name, ln)

        rep.score = min(100, sum(m.weight for m in rep.matches))
        rep.categories = {m.category for m in rep.matches}
        rep.severity = next(label for thr, label in SEVERITY_BANDS if rep.score >= thr)
        return rep


def find_skills(root: Path) -> list[Path]:
    """A skill package is any directory containing a SKILL.md (case-insensitive)."""
    skills: list[Path] = []
    for p in root.rglob("*"):
        if p.is_file() and p.name.lower() == "skill.md":
            skills.append(p.parent)
    if not skills and (root / "SKILL.md").exists():
        skills.append(root)
    return sorted(set(skills))


# --------------------------------------------------------------------------- #
# Scoping gate + file-flow chain analysis
# --------------------------------------------------------------------------- #
STATE_CHANGING = {"dangerous_action", "work_loop"}


@dataclass
class Scope:
    active: bool
    reason: str


def decide_scope(reports: list[SkillReport], trusted: set[str],
                 shared_workspace: bool) -> Scope:
    """
    Chain review is worth running only when: 2+ untrusted skills, a shared
    workspace, and at least one skill that can take a state-changing action.
    Otherwise per-skill review is enough.
    """
    untrusted = [r for r in reports if r.name not in trusted]
    has_state_change = any(r.categories & STATE_CHANGING for r in untrusted)
    if not shared_workspace:
        return Scope(False, "no shared workspace: skills cannot hand files to each other")
    if len(untrusted) < 2:
        return Scope(False, f"only {len(untrusted)} untrusted skill(s): nothing to chain")
    if not has_state_change:
        return Scope(False, "no untrusted skill can take a state-changing action")
    return Scope(True, f"{len(untrusted)} untrusted skills share a workspace and at "
                       f"least one can change state")


def analyze_chain(reports: list[SkillReport], trusted: set[str]) -> list[ChainFinding]:
    """
    File-flow chain: skill A writes file F, a DIFFERENT skill B reads file F and
    can take a state-changing action. If A also carries an authority claim, this
    is the paper's authority-promotion handoff and is rated CRITICAL.
    """
    findings: list[ChainFinding] = []
    considered = [r for r in reports if r.name not in trusted]

    # index: file basename -> skills that write / read it
    writers_of: dict[str, list[SkillReport]] = {}
    readers_of: dict[str, list[SkillReport]] = {}
    for r in considered:
        for f in r.writes:
            writers_of.setdefault(f, []).append(r)
        for f in r.reads:
            readers_of.setdefault(f, []).append(r)

    seen_pairs: set[tuple[str, str, str]] = set()
    matched_files: set[str] = set()
    for f, writers in writers_of.items():
        readers = readers_of.get(f, [])
        for w in writers:
            for rdr in readers:
                if w.name == rdr.name:
                    continue
                if not (rdr.categories & STATE_CHANGING):
                    continue
                key = (w.name, rdr.name, f)
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                matched_files.add(f)
                claim = "authority_promotion" in w.categories
                sev = "CRITICAL" if claim else "HIGH"
                note = (f"'{w.name}' writes `{f}` and '{rdr.name}' reads it before a "
                        f"state-changing action. ")
                note += ("The writer also frames progress as approval, so the record "
                         "can carry a false claim of user permission across the handoff "
                         "(authority promotion)."
                         if claim else
                         "No explicit approval phrase in the writer, but the file still "
                         "flows into a state-changing step; confirm the reader does not "
                         "treat its contents as permission.")
                findings.append(ChainFinding("precise", sev, f, [w.name],
                                             [rdr.name], claim, note))

    # Fallback: ingredients present across different skills but no shared file
    # matched (e.g. filename reworded or passed implicitly). Lower-confidence.
    if not matched_files:
        writers = [r.name for r in considered
                   if r.categories & {"record_write", "authority_promotion"}]
        consumers = [r.name for r in considered if "record_consume" in r.categories]
        dangerous = [r.name for r in considered if r.categories & STATE_CHANGING]
        cross = (set(writers) and set(consumers) and set(dangerous)
                 and not (set(writers) == set(consumers) == set(dangerous)
                          and len(set(writers)) == 1))
        if writers and consumers and dangerous and cross:
            findings.append(ChainFinding(
                "possible", "HIGH", None, sorted(set(writers)),
                sorted(set(consumers) | set(dangerous)), False,
                "A record-writer, a record-consumer, and a state-changing action exist "
                "across different skills, but no shared file was matched by name. The "
                "handoff may use a reworded or implicit filename. Review the set by hand."))
    return findings


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4}


def print_report(reports: list[SkillReport], chains: list[ChainFinding],
                 scope: Scope) -> None:
    reports = sorted(reports, key=lambda r: (SEV_ORDER[r.severity], -r.score, r.name))
    print("\n" + "=" * 70)
    print("  SkillSentry scan report")
    print("=" * 70)
    print(f"  skills scanned: {len(reports)}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"):
        n = sum(1 for r in reports if r.severity == sev)
        if n:
            print(f"    {sev:<9} {n}")
    print(f"  chain analysis: {'ACTIVE' if scope.active else 'skipped'} ({scope.reason})")
    print("=" * 70)

    for r in reports:
        if r.severity == "CLEAN":
            continue
        print(f"\n[{r.severity}]  {r.name}   (score {r.score}, path: {r.path})")
        print(f"  categories: {', '.join(sorted(r.categories))}")
        if r.writes:
            print(f"  writes: {', '.join(sorted(r.writes))}")
        if r.reads:
            print(f"  reads:  {', '.join(sorted(r.reads))}")
        for m in sorted(r.matches, key=lambda m: -m.weight)[:6]:
            print(f"    - {m.category}/{m.rule_id}  {m.file}:{m.line}")
            print(f"        …{m.excerpt}…")
        extra = len(r.matches) - min(len(r.matches), 6)
        if extra:
            print(f"    ... and {extra} more match(es)")

    if scope.active and chains:
        print("\n" + "!" * 70)
        print("  CROSS-SKILL CHAIN RISK (file-flow)")
        print("!" * 70)
        for c in sorted(chains, key=lambda c: SEV_ORDER[c.severity]):
            tag = "shared file" if c.kind == "precise" else "possible, no file match"
            print(f"\n  [{c.severity}] ({tag})")
            if c.file:
                print(f"    file:       {c.file}")
            print(f"    upstream:   {', '.join(c.upstream)}")
            print(f"    downstream: {', '.join(c.downstream)}")
            print(f"    -> {c.note}")
    elif scope.active:
        print("\n  chain analysis active: no cross-skill file handoff found.")

    clean = [r.name for r in reports if r.severity == "CLEAN"]
    if clean:
        print(f"\n  clean (per-skill): {', '.join(clean)}")
    print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Static analyzer for agent skill packages.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("scan", help="scan a directory of skill packages")
    sp.add_argument("path", type=Path, help="directory containing skill packages")
    sp.add_argument("--rules", type=Path, help="JSON file of extra/override rules")
    sp.add_argument("--json", type=Path, help="write full report as JSON here")
    sp.add_argument("--trusted", default="",
                    help="comma-separated skill names to treat as first-party/pinned")
    sp.add_argument("--shared-workspace", choices=["yes", "no"], default="yes",
                    help="do the skills share a working directory? (default yes)")
    sp.add_argument("--fail-on", default="HIGH",
                    choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    help="exit non-zero if any skill reaches this severity (CI gate)")
    args = ap.parse_args(argv)

    if not args.path.exists():
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    rules = list(DEFAULT_RULES)
    if args.rules:
        try:
            extra = json.loads(args.rules.read_text(encoding="utf-8"))
            rules.extend(extra)
            print(f"[info] loaded {len(extra)} extra rule(s) from {args.rules}",
                  file=sys.stderr)
        except (OSError, json.JSONDecodeError) as e:
            print(f"error: could not read rules: {e}", file=sys.stderr)
            return 2

    scanner = Scanner(rules)
    skill_dirs = find_skills(args.path)
    if not skill_dirs:
        print(f"[warn] no SKILL.md packages found under {args.path}", file=sys.stderr)
        return 0

    reports = [scanner.scan_skill(d, args.path) for d in skill_dirs]
    trusted = {s.strip() for s in args.trusted.split(",") if s.strip()}
    scope = decide_scope(reports, trusted, args.shared_workspace == "yes")
    chains = analyze_chain(reports, trusted) if scope.active else []
    print_report(reports, chains, scope)

    if args.json:
        payload = {
            "scope": asdict(scope),
            "trusted": sorted(trusted),
            "skills": [r.as_dict() for r in reports],
            "chain_findings": [asdict(c) for c in chains],
        }
        args.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"[info] JSON report written to {args.json}", file=sys.stderr)

    worst = min((SEV_ORDER[r.severity] for r in reports), default=4)
    gate = SEV_ORDER[args.fail_on]
    if chains or worst <= gate:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
