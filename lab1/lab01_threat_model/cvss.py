"""Калькулятор базової оцінки CVSS v3.1 (за специфікацією FIRST, розділ 7).

Використання:  python cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
"""
import math
import sys

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Вага PR залежить від області: (S:U, S:C)
PR_WEIGHTS = {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.5)}
METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse(vector: str) -> dict:
    parts = vector.strip().split("/")
    if parts[0] != "CVSS:3.1":
        raise ValueError("вектор має починатися з префікса CVSS:3.1")
    metrics = dict(p.split(":", 1) for p in parts[1:])
    if tuple(metrics) != METRICS:
        raise ValueError(f"очікувані метрики: {'/'.join(METRICS)}")
    for name, value in metrics.items():
        allowed = "UC" if name == "S" else PR_WEIGHTS if name == "PR" else WEIGHTS[name]
        if value not in allowed:
            raise ValueError(f"неприпустиме значення {name}:{value}")
    return metrics


def roundup(value: float) -> float:
    """Округлення вгору до одного знака (додаток A специфікації CVSS v3.1)."""
    i = round(value * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def subscores(vector: str) -> tuple[float, float]:
    """Повертає (підоцінка впливу, підоцінка експлуатованості)."""
    m = parse(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - WEIGHTS["C"][m["C"]]) * (1 - WEIGHTS["I"][m["I"]]) * (1 - WEIGHTS["A"][m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = (8.22 * WEIGHTS["AV"][m["AV"]] * WEIGHTS["AC"][m["AC"]]
                      * PR_WEIGHTS[m["PR"]][changed] * WEIGHTS["UI"][m["UI"]])
    return impact, exploitability


def base_score(vector: str) -> float:
    impact, exploitability = subscores(vector)
    if impact <= 0:
        return 0.0
    if parse(vector)["S"] == "C":
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity(score: float) -> str:
    if score == 0:
        return "немає"
    if score < 4:
        return "низький"
    if score < 7:
        return "середній"
    if score < 9:
        return "високий"
    return "критичний"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    print(sys.argv[1])
    print(f"базова оцінка: {base_score(sys.argv[1])}")
