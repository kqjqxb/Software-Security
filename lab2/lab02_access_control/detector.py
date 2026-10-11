"""Детектор аномалій варіанта 12: А1 (сплеск відмов) і А3 (перебір ідентифікаторів)."""
from __future__ import annotations

import collections
import re
from datetime import datetime, timedelta

from accesscontrol.monitor import AnomalyDetector, AuditLog

_NUMBER = re.compile(r"(\d+)$")


class VariantDetector(AnomalyDetector):
    def __init__(self, deny_threshold: int = 5, window_seconds: int = 60, run_threshold: int = 5) -> None:
        self.deny_threshold = deny_threshold
        self.window = timedelta(seconds=window_seconds)
        self.run_threshold = run_threshold

    def scan(self, log: AuditLog) -> list[str]:
        entries = log.entries()
        return self._deny_bursts(entries) + self._enumerations(entries)

    def _deny_bursts(self, entries: list[dict]) -> list[str]:
        denials: dict[str, list[datetime]] = collections.defaultdict(list)
        for entry in entries:
            if not entry["allowed"]:
                denials[entry["subject"]].append(datetime.fromisoformat(entry["ts"]))

        alerts = []
        for subject, moments in denials.items():
            moments.sort()
            peak, start = 0, 0
            for end, moment in enumerate(moments):
                while moment - moments[start] > self.window:
                    start += 1
                peak = max(peak, end - start + 1)
            if peak >= self.deny_threshold:
                alerts.append(f"А1: сплеск відмов — {subject}: {peak} відмов за "
                              f"{int(self.window.total_seconds())} с (поріг {self.deny_threshold})")
        return alerts

    def _enumerations(self, entries: list[dict]) -> list[str]:
        requested: dict[str, list[str]] = collections.defaultdict(list)
        for entry in entries:
            objects = requested[entry["subject"]]
            if not objects or objects[-1] != entry["object"]:
                objects.append(entry["object"])

        alerts = []
        for subject, objects in requested.items():
            first, last = self._longest_run(objects)
            length = last - first + 1
            if length >= self.run_threshold:
                alerts.append(f"А3: послідовний перебір — {subject}: {length} об'єктів поспіль "
                              f"({objects[first]}…{objects[last]}, поріг {self.run_threshold})")
        return alerts

    @staticmethod
    def _longest_run(objects: list[str]) -> tuple[int, int]:
        """Межі найдовшої серії звернень, у якій номер об'єкта щоразу змінюється на 1 в один бік."""
        numbers = [int(m.group(1)) if (m := _NUMBER.search(name)) else None for name in objects]
        best = (0, -1)
        start, step = 0, 0
        for i, number in enumerate(numbers):
            previous = numbers[i - 1] if i else None
            delta = number - previous if number is not None and previous is not None else None
            if delta not in (1, -1):
                start, step = i, 0
            elif delta != step:
                start, step = i - 1, delta
            if number is not None and i - start > best[1] - best[0]:
                best = (start, i)
        return best
