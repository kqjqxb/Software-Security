"""Критерій проходження (quality gate) лабораторної роботи 6, варіант 12.

Блокує складання за наявності секрету в діффі. Ознак секрету дві:
знахідка gitleaks у комітах діффу та збіг власного правила Semgrep
(жорстко закодований секрет сесії, CWE-798) на рядку, доданому діффом.
"""
from __future__ import annotations

import json
import os
import re
import sys

SECRET_RULE = "my-lomakin-hardcoded-secret-key"
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def load(path: str) -> dict | list | None:
    """Читає JSON-звіт. Повертає None, якщо звіту немає або його пошкоджено."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def read_text(path: str) -> str | None:
    """Читає текстовий файл. Повертає None, якщо файла немає."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def bandit_high(report: dict) -> int:
    return sum(1 for r in report.get("results", [])
               if r.get("issue_severity") == "HIGH")


def gitleaks_secrets(report: list) -> list[str]:
    """Знахідки gitleaks у вигляді «правило файл:рядок» без значення секрету."""
    return [f"{r.get('RuleID')} {r.get('File')}:{r.get('StartLine')}"
            for r in report]


def added_lines(diff: str) -> dict[str, set[int]]:
    """Номери рядків, доданих діффом (формат git diff -U0), за файлами."""
    added: dict[str, set[int]] = {}
    path = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            name = line[4:].strip()
            path = None if name == "/dev/null" else name.removeprefix("b/")
        elif path and (m := HUNK.match(line)):
            start, count = int(m.group(1)), int(m.group(2) or "1")
            added.setdefault(path, set()).update(range(start, start + count))
    return added


def rule_secrets(semgrep: dict, added: dict[str, set[int]],
                 rule: str = SECRET_RULE) -> list[str]:
    """Збіги власного правила Semgrep, що припадають на додані рядки."""
    hits = []
    for r in semgrep.get("results", []):
        if not r.get("check_id", "").endswith(rule):
            continue
        lines = range(r["start"]["line"], r["end"]["line"] + 1)
        if added.get(r["path"], set()).intersection(lines):
            hits.append(f"{rule} {r['path']}:{r['start']['line']}")
    return hits


def main() -> int:
    bandit = load("bandit.json")
    if bandit is None:
        # Відсутній або пошкоджений звіт означає збій сканера, а не «0 знахідок».
        # Критерій має відмовляти в разі збою (fail closed): у конвеєрі сканер
        # запускається з `|| true`, тож інакше його падіння непомітно пропустило б
        # вразливий код у складання.
        print("::error::Quality gate: звіт bandit.json відсутній або пошкоджений"
              " — складання заблоковано")
        return 1
    high = bandit_high(bandit)
    print(f"Знахідок Bandit рівня HIGH: {high}")
    # Критерій HIGH не належить варіанту 12: діє, лише якщо задано MAX_HIGH.
    threshold = os.environ.get("MAX_HIGH")
    if threshold is not None and high > int(threshold):
        print(f"::error::Quality gate: {high} знахідок HIGH перевищує поріг"
              f" {threshold}")
        return 1

    gitleaks, semgrep = load("gitleaks.json"), load("semgrep.json")
    diff = read_text("diff.patch")
    missing = [name for name, value in (("gitleaks.json", gitleaks),
               ("semgrep.json", semgrep), ("diff.patch", diff)) if value is None]
    if missing or not isinstance(gitleaks, list) or not isinstance(semgrep, dict):
        print("::error::Quality gate: звіт для критерію секретів відсутній або"
              f" пошкоджений ({', '.join(missing) or 'невірний формат'})"
              " — складання заблоковано")
        return 1
    leaks = gitleaks_secrets(gitleaks)
    hardcoded = rule_secrets(semgrep, added_lines(diff))
    print(f"Секретів у діффі за gitleaks: {len(leaks)}")
    print(f"Збігів правила {SECRET_RULE} на доданих рядках: {len(hardcoded)}")
    if leaks or hardcoded:
        for item in leaks + hardcoded:
            print(f"::error::Quality gate: секрет у діффі — {item}")
        return 1
    print("Quality gate: пройдено")
    return 0


if __name__ == "__main__":
    sys.exit(main())
