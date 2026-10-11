"""Параметри індивідуальних завдань лабораторної роботи 1.

Запуск:  python -m common.variants <N> --lab 1
"""
import argparse
import json

SYSTEMS = [
    "сервіс приймання показань лічильників",
    "сервіс зберігання резервних копій проєктів",
    "мобільний застосунок обліку особистих фінансів",
    "система контролю доступу до лабораторії за перепустками",
    "система обліку відвідуваності занять",
    "система моніторингу серверів із сповіщеннями",
    "платформа онлайн-курсів із перевіркою завдань",
    "агрегатор вакансій із відгуками роботодавців",
    "маркетплейс вживаних підручників",
    "вебсервіс запису на прийом до лікаря",
    "система бронювання аудиторій університету",
    "внутрішній чат-сервіс компанії",
    "платформа електронного голосування студради",
    "система електронного документообігу кафедри",
    "сервіс обміну файлами між студентами",
]
CATEGORIES = [
    "підміна даних (Tampering)",
    "підвищення привілеїв (Elevation of privilege)",
    "спуфінг (Spoofing)",
    "розкриття інформації (Information disclosure)",
    "відмова від авторства (Repudiation)",
]
# Варіанти 16–30 повторюють перелік систем зі зсувом (таблиця 1.5).
SYSTEM_ORDER = list(range(15)) + list(range(4, 15)) + list(range(0, 4))
CATEGORY_ORDER = [i % 5 for i in range(15)] + [(i + 2) % 5 for i in range(15)]


def lab1(n: int) -> dict:
    if not 1 <= n <= 30:
        raise SystemExit("Номер варіанта має бути в межах 1–30")
    return {
        "variant": n,
        "lab": 1,
        "system": SYSTEMS[SYSTEM_ORDER[n - 1]],
        "focus_category": CATEGORIES[CATEGORY_ORDER[n - 1]],
        "min_threats": 12,
        "min_high_risk": 3,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Параметри індивідуального варіанта")
    parser.add_argument("n", type=int, help="номер здобувача у списку групи")
    parser.add_argument("--lab", type=int, default=1)
    args = parser.parse_args()
    if args.lab != 1:
        raise SystemExit("Доступні лише параметри лабораторної роботи 1")
    print(json.dumps(lab1(args.n), ensure_ascii=False, indent=2))
