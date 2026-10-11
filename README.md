# Безпека програмного забезпечення

Лабораторні роботи з дисципліни «Безпека програмного забезпечення», КПІ ім. Ігоря Сікорського, ФІОТ.

Виконав: Максим Ломакін, група ІП-33.

| № | Тема | Папка |
|---|------|-------|
| 1 | Побудова моделі загроз програмного застосунку (варіант 12) | [lab1](lab1) |
| 2 | Розроблення підсистеми розмежування доступу (варіант 12) | [lab2](lab2) |

## Лабораторна робота 1

Об'єкт моделювання – внутрішній чат-сервіс компанії, пріоритетна категорія STRIDE – Elevation of privilege.

- `lab1/звіт_лр1/threat_model.md` – модель загроз (сім розділів);
- `lab1/звіт_лр1/dfd.mmd`, `dfd.png` – діаграма потоків даних із межами довіри;
- `lab1/lab01_threat_model/cvss.py` – калькулятор базової оцінки CVSS v3.1;
- `lab1/lab01_threat_model/scoring.py` – вектори й оцінки загроз;
- `lab1/report/` – звіт у форматі PDF.

```bash
cd lab1
python3 -m common.variants 12 --lab 1
cd lab01_threat_model && python3 scoring.py
```

## Лабораторна робота 2

Диспетчер доступу за моделлю ABAC із заборонними записами (deny), детектор аномалій А1 (сплеск відмов) і А3 (послідовний перебір ідентифікаторів); 8 суб'єктів, 21 об'єкт.

- `lab2/lab02_access_control/accesscontrol/monitor.py` – каркас диспетчера доступу;
- `lab2/lab02_access_control/mypolicy.py` – політика `VariantPolicy` та її наповнення;
- `lab2/lab02_access_control/detector.py` – детектор аномалій;
- `lab2/lab02_access_control/storage.py` – сховище документів і операційний журнал;
- `lab2/lab02_access_control/demo.py` – демонстрація роботи підсистеми;
- `lab2/lab02_access_control/tests/test_variant.py` – модульні тести;
- `lab2/report/` – звіт у форматі PDF.

```bash
cd lab2
python3 -m common.variants 12 --lab 2
cd lab02_access_control
pip install -r requirements.txt
PYTHONPATH=. pytest tests/test_variant.py -q
PYTHONPATH=. python3 demo.py
```
