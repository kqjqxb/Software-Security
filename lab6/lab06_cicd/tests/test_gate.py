"""Тести критерію проходження, власних правил Semgrep і файла конвеєра."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import gate

ROOT = Path(__file__).resolve().parent.parent
SEMGREP = Path(sys.executable).parent / "semgrep"
RULE = gate.SECRET_RULE

DIFF = """\
diff --git a/target/app.py b/target/app.py
--- a/target/app.py
+++ b/target/app.py
@@ -33,0 +34,2 @@ app = Flask(__name__)
+first
+second
@@ -50 +52 @@ def db():
+third
@@ -60,2 +61,0 @@ def gone():
-removed
-removed
diff --git a/old.py b/old.py
--- a/old.py
+++ /dev/null
@@ -1,3 +0,0 @@
-a
diff --git a/new.py b/new.py
--- /dev/null
+++ b/new.py
@@ -0,0 +1 @@
+x = 1
"""


def finding(rule, path, line):
    return {"check_id": f"rules.{rule}", "path": path,
            "start": {"line": line}, "end": {"line": line}}


def write_reports(tmp_path, leaks=(), findings=(), diff="", high=0):
    results = [{"issue_severity": "HIGH"}] * high
    (tmp_path / "bandit.json").write_text(json.dumps({"results": results}))
    (tmp_path / "gitleaks.json").write_text(json.dumps(list(leaks)))
    semgrep = {"results": list(findings)}
    (tmp_path / "semgrep.json").write_text(json.dumps(semgrep))
    (tmp_path / "diff.patch").write_text(diff)


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MAX_HIGH", raising=False)
    return tmp_path


def test_bandit_high_counts_only_high():
    report = {"results": [{"issue_severity": "HIGH"}, {"issue_severity": "LOW"},
                          {"issue_severity": "HIGH"}]}
    assert gate.bandit_high(report) == 2


def test_added_lines_parses_hunks():
    added = gate.added_lines(DIFF)
    assert added == {"target/app.py": {34, 35, 52}, "new.py": {1}}


def test_added_lines_of_empty_diff():
    assert gate.added_lines("") == {}


def test_gitleaks_secrets_do_not_expose_value():
    report = [{"RuleID": "generic-api-key", "File": "a.py", "StartLine": 2,
               "Secret": "value", "Match": "KEY = value"}]
    assert gate.gitleaks_secrets(report) == ["generic-api-key a.py:2"]


def test_rule_secrets_only_on_added_lines():
    semgrep = {"results": [finding(RULE, "target/app.py", 34),
                           finding(RULE, "target/app.py", 90),
                           finding(RULE, "target/other.py", 34),
                           finding("python-eval-untrusted", "target/app.py", 35)]}
    hits = gate.rule_secrets(semgrep, gate.added_lines(DIFF))
    assert hits == [f"{RULE} target/app.py:34"]


def test_gate_passes_on_clean_diff(workdir, capsys):
    write_reports(workdir, diff=DIFF)
    assert gate.main() == 0
    assert "Quality gate: пройдено" in capsys.readouterr().out


def test_gate_blocks_on_gitleaks_finding(workdir, capsys):
    leak = {"RuleID": "generic-api-key", "File": "a.py", "StartLine": 2}
    write_reports(workdir, leaks=[leak])
    assert gate.main() == 1
    assert "::error::Quality gate: секрет у діффі" in capsys.readouterr().out


def test_gate_blocks_on_rule_match_in_diff(workdir, capsys):
    hit = finding(RULE, "target/app.py", 34)
    write_reports(workdir, findings=[hit], diff=DIFF)
    assert gate.main() == 1
    assert f"{RULE} target/app.py:34" in capsys.readouterr().out


def test_gate_ignores_rule_match_outside_diff(workdir):
    hit = finding(RULE, "target/app.py", 90)
    write_reports(workdir, findings=[hit], diff=DIFF)
    assert gate.main() == 0


def test_gate_ignores_other_rules_and_high_by_default(workdir):
    other = finding("python-subprocess-shell-true", "target/app.py", 34)
    write_reports(workdir, findings=[other], diff=DIFF, high=3)
    assert gate.main() == 0


def test_max_high_threshold_is_optional(workdir, monkeypatch):
    write_reports(workdir, high=3)
    monkeypatch.setenv("MAX_HIGH", "2")
    assert gate.main() == 1
    monkeypatch.setenv("MAX_HIGH", "3")
    assert gate.main() == 0


@pytest.mark.parametrize("name", ["bandit.json", "gitleaks.json", "semgrep.json",
                                  "diff.patch"])
def test_gate_fails_closed_without_report(workdir, name, capsys):
    write_reports(workdir)
    (workdir / name).unlink()
    assert gate.main() == 1
    assert "::error::" in capsys.readouterr().out


def test_gate_fails_closed_on_broken_report(workdir):
    write_reports(workdir)
    (workdir / "gitleaks.json").write_text("{not json")
    assert gate.main() == 1


def run_rules(target):
    out = subprocess.run([SEMGREP, "--config", ROOT / "rules", "--json",
                          "--metrics=off", "-q", target.name],
                         cwd=target.parent, capture_output=True, text=True)
    return [(r["check_id"].split(".")[-1], r["path"], r["start"]["line"])
            for r in json.loads(out.stdout)["results"]]


needs_semgrep = pytest.mark.skipif(
    not SEMGREP.exists() or not (ROOT / "target").exists(),
    reason="потрібні semgrep і каталог target/")


@needs_semgrep
def test_own_rules_match_real_code():
    hits = run_rules(ROOT / "target")
    assert (RULE, "target/app.py", 34) in hits
    assert [h for h in hits if h[0] == "my-lomakin-admin-route-no-authz"] == [
        ("my-lomakin-admin-route-no-authz", "target/app.py", 213),
        ("my-lomakin-admin-route-no-authz", "target/app.py", 221)]
    safe = sorted(h[1] for h in hits if h[0] == "my-lomakin-jinja-safe-filter")
    assert safe == ["target/templates/document.html",
                    "target/templates/search.html"]


@needs_semgrep
def test_fix_removes_secret_rule_match(tmp_path):
    shutil.copytree(ROOT / "target", tmp_path / "target")
    patch = ROOT / "fix" / "secret_key.patch"
    subprocess.run(["patch", "-p1", "-s", "-i", patch], cwd=tmp_path, check=True)
    assert RULE not in [h[0] for h in run_rules(tmp_path / "target")]


def test_workflow_structure():
    text = (ROOT / ".github" / "workflows" / "security.yml").read_text("utf-8")
    flow = yaml.safe_load(text)
    assert flow["permissions"] == {"contents": "read"}
    assert set(flow["jobs"]) == {"sast", "sca", "secrets"}
    steps = [s.get("name") for s in flow["jobs"]["sast"]["steps"]]
    assert steps.index("Діфф і секрети в діффі") < steps.index("Quality gate")
    runs = [s.get("run", "") for s in flow["jobs"]["sast"]["steps"]]
    assert "python gate.py" in runs
    assert flow["jobs"]["sast"]["steps"][0]["with"]["fetch-depth"] == 0
