# Безпека програмного забезпечення

Лабораторні роботи з дисципліни «Безпека програмного забезпечення», КПІ ім. Ігоря Сікорського, ФІОТ.

Виконав: Максим Ломакін, група ІП-33.

| № | Тема | Папка |
|---|------|-------|
| 1 | Побудова моделі загроз програмного застосунку (варіант 12) | [lab1](lab1) |
| 2 | Розроблення підсистеми розмежування доступу (варіант 12) | [lab2](lab2) |
| 3 | Розроблення підсистеми ідентифікації та автентифікації (варіант 12) | [lab3](lab3) |
| 4 | Дослідження та реалізація криптографічних механізмів (варіант 12) | [lab4](lab4) |
| 6 | Автоматизований контроль захищеності у конвеєрі CI/CD (варіант 12) | [lab6](lab6) |

## Лабораторна робота 1

Об'єкт моделювання – внутрішній чат-сервіс компанії, пріоритетна категорія STRIDE – Elevation of privilege.

- `lab1/звіт_лр1/threat_model.md` – модель загроз (сім розділів);
- `lab1/звіт_лр1/dfd.mmd`, `dfd.png` – діаграма потоків даних із межами довіри;
- `lab1/lab01_threat_model/scoring.py` – вектори й оцінки загроз;
- `lab1/report/` – звіт у форматі PDF.

```bash
cd lab1
python3 -m common.variants 12 --lab 1
cd lab01_threat_model && python3 scoring.py
```

## Лабораторна робота 2

Диспетчер доступу за моделлю ABAC із заборонними записами (deny), детектор аномалій А1 (сплеск відмов) і А3 (послідовний перебір ідентифікаторів); 8 суб'єктів, 21 об'єкт.

- `lab2/lab02_access_control/mypolicy.py` – політика `VariantPolicy` та її наповнення;
- `lab2/lab02_access_control/detector.py` – детектор аномалій;
- `lab2/lab02_access_control/storage.py` – сховище документів і операційний журнал;
- `lab2/lab02_access_control/demo.py` – демонстрація роботи підсистеми;
- `lab2/lab02_access_control/tests/test_variant.py` – власні модульні тести;
- `lab2/report/` – звіт у форматі PDF.

```bash
cd lab2
python3 -m common.variants 12 --lab 2
cd lab02_access_control
pip install -r requirements.txt
PYTHONPATH=. pytest tests/ -q
PYTHONPATH=. python3 demo.py
```

## Лабораторна робота 3

Зберігання паролів за PBKDF2-HMAC-SHA256 із сіллю та «перцем», фіксоване блокування на 15 хв після 5 невдалих спроб, одноразові коди відновлення, розрахунок за формулою Андерсона.

```bash
cd lab3/lab03_auth
pip install -r requirements.txt
PYTHONPATH=. pytest tests/ -q
PYTHONPATH=. python3 demo.py
```

Звіт – `lab3/report/`.

## Лабораторна робота 4

Навчальний RSA з 32-бітовими множниками, автентифіковане шифрування ChaCha20-Poly1305, підпис RSA-PSS (2048), приклади хибного застосування: статичний вектор ініціалізації в CBC та порядок MAC і шифрування.

```bash
cd lab4/lab04_crypto
pip install -r requirements.txt
PYTHONPATH=. pytest tests/ -q
PYTHONPATH=. python3 -m crypto_lab.aead_demo
```

Звіт – `lab4/report/`.

## Лабораторна робота 6

Конвеєр перевірок безпеки: Semgrep із власними правилами, Bandit, pip-audit, SBOM (CycloneDX), gitleaks і критерій проходження, що блокує складання за наявності секрету в діффі.

```bash
cd lab6/lab06_cicd
pip install -r requirements.txt
PYTHONPATH=. pytest tests/ -q
```

Звіт – `lab6/report/`.

## Матеріали курсу

Генератор варіантів `common/variants.py`, калькулятор `lab01_threat_model/cvss.py`, шаблони `lab01_threat_model/templates/`, каркас `lab02_access_control/accesscontrol/monitor.py`, навчальний приклад `examples/blp_example.py`, тести `tests/test_example.py`, а також каркаси `lab03_auth`, `lab04_crypto` і `lab06_cicd` узято із [репозиторію курсу](https://github.com/sokolusha/software-security-course) (© 2026 Соколовський В. В., ліцензія MIT).
