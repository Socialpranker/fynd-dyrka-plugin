#!/usr/bin/env python3
"""Инвариант диеты SKILL.md: перенос не должен превращаться в потерю.

Секция, уехавшая в `references/`, полезна ровно до тех пор, пока SKILL.md
посылает её читать. Файл, на который никто не ссылается, — это не экономия
контекста, а вырезанный кусок инструкции: он есть на диске и недостижим.

Проверяет три вещи:
  1. каждый references/*.md упомянут в SKILL.md (иначе сирота);
  2. каждая ссылка вида `references/x.md` из SKILL.md ведёт в существующий файл;
  3. SKILL.md не вырос сверх бюджета.

Бюджет в БАЙТАХ, не в токенах: текст кириллический, отношение байт/токен
плавает по моделям, а байты — то, что можно проверить без сети. 70 000 —
потолок после диеты 27.08.2026 (было 85 814, стало 67 311).

Запуск:  python3 scripts/check_refs.py [--ci]
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
            issues.append("СИРОТА: references/%s ни разу не упомянут в SKILL.md" % name)

    for m in re.findall(r"references/([A-Za-z0-9_.-]+\.md)", text):
        if not os.path.exists(os.path.join(REFS, m)):
            issues.append("БИТАЯ ССЫЛКА: SKILL.md → references/%s не существует" % m)

    print("SKILL.md: %d байт (бюджет %d)" % (size, BUDGET_BYTES))
    print("references: %d файлов, все достижимы" % len(on_disk)
          if not issues else "references: %d файлов" % len(on_disk))
    if size > BUDGET_BYTES:
        issues.append("БЮДЖЕТ: SKILL.md %d > %d байт — переноси секцию в references,"
                      " а не ужимай формулировки" % (size, BUDGET_BYTES))

    for i in issues:
        print("  ✗ " + i)
    if issues:
        print("НЕ ПРОШЛО: %d" % len(issues))
        return 1
    print("✅ чисто")
    return 0

if __name__ == "__main__":
    sys.exit(main())
