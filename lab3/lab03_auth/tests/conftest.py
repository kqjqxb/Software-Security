"""Тестове середовище: «перець» задається до імпорту auth.passwords."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
# ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
os.environ["AUTH_PEPPER"] = "lab3-synthetic-pepper"
