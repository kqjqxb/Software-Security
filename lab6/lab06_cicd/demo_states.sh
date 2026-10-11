#!/usr/bin/env bash
# Відтворює стадію sast конвеєра в тимчасовому git-репозиторії та показує
# чотири стани критерію проходження. Запуск: ./demo_states.sh <порожній каталог>
set -u
src="$(cd "$(dirname "$0")" && pwd)"
work="${1:?вкажіть порожній каталог для тимчасового репозиторію}"
export PATH="$src/.venv/bin:$PATH"
mkdir -p "$work" && cd "$work" || exit 2
[ -z "$(ls -A .)" ] || { echo "каталог $work не порожній"; exit 2; }

commit() {
  git add -A && git -c user.name=lab6 -c user.email=lab6@stand.local \
    commit -q -m "$1" && git rev-parse --short HEAD
}

sast() {  # $1 – базовий коміт діффу (порожньо – уся історія)
  bandit -r target -f json -o bandit.json -q 2>/dev/null || true
  semgrep --config rules/ --config "p/python" --json --output semgrep.json \
    target -q 2>/dev/null || true
  ci/diff_reports.sh "$1" 2>/dev/null
  python gate.py
  echo "код завершення: $?"
}

git init -q -b main .
printf '%s\n' '*.json' 'diff.patch' > .gitignore
cp -R "$src/gate.py" "$src/rules" "$src/ci" "$src/audit_target.txt" \
  "$src/requirements.txt" "$src/.github" "$src/target" .

echo "== Стан 1: застосунок ЛР5 додано до репозиторію =="
c1="$(commit 'Конвеєр і ціль аналізу')"
echo "коміт: $c1"
sast ""

echo "== Стан 2: секрет сесії читається лише з оточення =="
git apply "$src/fix/secret_key.patch"
c2="$(commit 'Секрет сесії без значення за замовчуванням')"
echo "коміт: $c2"
sast "$c1"

echo "== Стан 3: до коміту потрапив тестовий ключ =="
# Ключ-пустушку складено з двох частин, щоб його не було в цьому файлі.
printf '%s\nLAB6_FAKE_API_KEY = "%s%s"\n' \
  '# ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом' \
  '0f1e2d3c4b5a6978' '8796a5b4c3d2e1f0' > target/settings_local.py
c3="$(commit 'Локальні налаштування')"
echo "коміт: $c3"
sast "$c2"
echo "-- gitleaks detect --no-git (робоче дерево) --"
gitleaks detect --source target --no-git --no-banner --report-format json \
  --report-path tree.json 2>/dev/null
echo "код завершення gitleaks: $?"
python -c "import json; [print(r['RuleID'], r['File'], r['StartLine'], \
r['Match']) for r in json.load(open('tree.json'))]"

echo "== Стан 4: тестовий ключ вилучено =="
git rm -q target/settings_local.py
c4="$(commit 'Вилучено локальні налаштування')"
echo "коміт: $c4"
sast "$c3"
echo "-- gitleaks detect --no-git (робоче дерево) --"
gitleaks detect --source target --no-git --no-banner --report-format json \
  --report-path tree.json 2>/dev/null
echo "код завершення gitleaks: $?"
echo "записів у звіті: $(python -c "import json
print(len(json.load(open('tree.json'))))")"
echo "-- gitleaks detect (уся історія) --"
gitleaks detect --source . --redact --no-banner --report-format json \
  --report-path history.json 2>/dev/null
echo "код завершення gitleaks: $?"
python -c "import json; [print(r['RuleID'], r['File'], r['Commit'][:7]) \
for r in json.load(open('history.json'))]"
