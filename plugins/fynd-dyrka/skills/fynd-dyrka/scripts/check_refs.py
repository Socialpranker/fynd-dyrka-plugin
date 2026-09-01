#!/usr/bin/env python3
"""Invariant for the SKILL.md diet: moving a section must not lose it.

A section that moved into `references/` is useful exactly as long as SKILL.md
still sends the reader to it. A file nobody references is not saved context — it
is a cut-out piece of instruction: present on disk and unreachable.

Checks three things:
  1. every references/*.md is mentioned in SKILL.md (otherwise it is an orphan);
  2. every `references/x.md` link in SKILL.md resolves to an existing file;
  3. SKILL.md has not grown past its budget.

The budget is in BYTES, not tokens: the byte-per-token ratio drifts between
models, while bytes are checkable without a network call. 70,000 is the ceiling
set after the 2026-08-27 diet (85,814 → 67,311); the English translation later
brought it to ~45,600.

Run:  python3 scripts/check_refs.py [--ci]
"""
import os, re, sys

BUDGET_BYTES = 70_000
HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
SKILL = os.path.join(SKILL_DIR, "SKILL.md")
REFS = os.path.join(SKILL_DIR, "references")

def main() -> int:
    text = open(SKILL, encoding="utf-8").read()
    size = len(text.encode("utf-8"))
    issues = []

    on_disk = sorted(f for f in os.listdir(REFS) if f.endswith(".md"))
    for name in on_disk:
        if name not in text:
            issues.append("ORPHAN: references/%s is never mentioned in SKILL.md" % name)

    for m in re.findall(r"references/([A-Za-z0-9_.-]+\.md)", text):
        if not os.path.exists(os.path.join(REFS, m)):
            issues.append("BROKEN LINK: SKILL.md -> references/%s does not exist" % m)

    print("SKILL.md: %d bytes (budget %d)" % (size, BUDGET_BYTES))
    print("references: %d files, all reachable" % len(on_disk)
          if not issues else "references: %d files" % len(on_disk))
    if size > BUDGET_BYTES:
        issues.append("BUDGET: SKILL.md %d > %d bytes — move a section into"
                      " references instead of compressing wording" % (size, BUDGET_BYTES))

    for i in issues:
        print("  x " + i)
    if issues:
        print("FAILED: %d" % len(issues))
        return 1
    print("OK: clean")
    return 0

if __name__ == "__main__":
    sys.exit(main())
