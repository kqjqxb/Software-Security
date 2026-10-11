#!/usr/bin/env bash
# Готує для gate.py звіти про діфф BASE..HEAD: diff.patch і gitleaks.json.
# Якщо BASE не задано або такого коміту немає, діффом вважається вся історія.
set -u
base="${1:-}"
if [ -n "$base" ] && git cat-file -e "${base}^{commit}" 2>/dev/null; then
  range="${base}..HEAD"
else
  base="$(git hash-object -t tree /dev/null)"
  range="HEAD"
fi
echo "Діфф: ${range}"
git diff -U0 --no-color "$base" HEAD > diff.patch
# --redact: значення секрету до звіту не потрапляє.
gitleaks detect --source . --log-opts="$range" --redact --no-banner \
  --report-format json --report-path gitleaks.json || true
