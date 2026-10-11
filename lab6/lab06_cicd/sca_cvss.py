"""Доповнює звіт pip-audit оцінками CVSS v3.1 з бази NVD.

pip-audit подає ідентифікатор вразливості та версії з виправленням, але не
оцінку CVSS, тому її отримують за псевдонімом CVE. Якщо джерел кілька,
береться найбільша базова оцінка. Запуск: python sca_cvss.py
"""
from __future__ import annotations

import json
import time

import requests

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="


def nvd_scores(cve: str) -> list[dict]:
    """Оцінки CVSS v3.1 одного запису CVE: джерело, базова оцінка, вектор."""
    resp = requests.get(NVD + cve, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    metrics = data["vulnerabilities"][0]["cve"].get("metrics", {})
    return [{"source": m["source"], "score": m["cvssData"]["baseScore"],
             "vector": m["cvssData"]["vectorString"]}
            for m in metrics.get("cvssMetricV31", [])]


def collect(audit: dict, pause: float = 7.0) -> list[dict]:
    """Рядок на кожну вразливість звіту pip-audit з найбільшою оцінкою CVSS."""
    rows = []
    for dep in audit["dependencies"]:
        for vuln in dep.get("vulns", []):
            cve = next((a for a in vuln["aliases"] if a.startswith("CVE-")), None)
            scores = nvd_scores(cve) if cve else []
            best = max(scores, key=lambda s: s["score"], default=None)
            rows.append({
                "package": dep["name"], "version": dep["version"],
                "id": vuln["id"], "cve": cve, "fix": vuln["fix_versions"],
                "cvss": best["score"] if best else None,
                "vector": best["vector"] if best else None,
                "sources": scores,
            })
            time.sleep(pause)  # NVD без ключа дозволяє 5 запитів за 30 с
    return rows


def blocked(rows: list[dict], threshold: float) -> list[dict]:
    """Вразливості, які зупинили б складання за порогом CVSS."""
    return [r for r in rows if r["cvss"] is not None and r["cvss"] >= threshold]


if __name__ == "__main__":
    with open("pip-audit.json", encoding="utf-8") as fh:
        result = collect(json.load(fh))
    with open("cvss.json", "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    for row in result:
        print(f"{row['package']:7} {row['version']:7} {row['id']:16} "
              f"{row['cve']:15} CVSS {row['cvss']}")
    for limit in (7.0, 4.0):
        print(f"поріг {limit}: блокують {len(blocked(result, limit))} "
              f"із {len(result)}")
