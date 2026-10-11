"""Демонстрація підсистеми розмежування доступу (кроки 3–7)."""
from datetime import datetime, timedelta

from accesscontrol.monitor import AuditLog, Permission, ReferenceMonitor, subjects_with_access
from detector import VariantDetector
from mypolicy import OBJECTS, SUBJECTS, build_policy, objects_accessible_by
from storage import DocumentStore, OperationLog

R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE

# (суб'єкт, об'єкт, дія, очікуване рішення)
EXPECTED = [
    ("alice", "doc2", R, True),
    ("alice", "doc2", R | W, True),
    ("alice", "doc2", Permission.ADMIN, False),
    ("alice", "doc4", R, False),
    ("alice", "doc8", R, True),
    ("alice", "doc9", R, False),
    ("heidi", "doc2", R, False),
    ("heidi", "doc6", W, True),
    ("bob", "doc4", D, True),
    ("bob", "doc3", R, True),
    ("bob", "doc3", W, False),
    ("bob", "doc3", D, False),
    ("dave", "doc12", W, False),
    ("erin", "doc16", R, False),
    ("erin", "doc15", R, False),
    ("grace", "doc11", R, True),
    ("grace", "doc11", W, False),
    ("grace", "doc17", R, False),
    ("mallory", "doc1", R, False),
    ("alice", "doc99", R, False),
]


class Clock:
    """Керований годинник, щоб вивід демонстрації був відтворюваним."""

    def __init__(self, start: datetime, step: timedelta) -> None:
        self.now = start
        self.step = step

    def __call__(self) -> datetime:
        self.now += self.step
        return self.now


def verdict(allowed: bool) -> str:
    return "дозвіл" if allowed else "відмова"


def show_decisions(policy) -> None:
    base = build_policy(with_deny=False)
    print(f"{'суб’єкт':<8}{'об’єкт':<7}{'дія':<11}{'очікувано':<10}{'фактично':<10}{'без deny':<10}причина")
    for subject, obj, action, expected in EXPECTED:
        actual = policy.evaluate(subject, obj, action)
        without_deny = base.evaluate(subject, obj, action)
        assert actual.allowed == expected
        print(f"{subject:<8}{obj:<7}{action.name:<11}{verdict(expected):<10}{verdict(actual.allowed):<10}"
              f"{verdict(without_deny.allowed):<10}{actual.reason}")


def work_day(monitor: ReferenceMonitor, store: DocumentStore) -> int:
    """Звичайна робота користувачів; повертає кількість звернень до монітора."""
    operations = [
        lambda: store.read("alice", "doc2"),
        lambda: store.write("alice", "doc2", "специфікація, версія 2"),
        lambda: store.read("alice", "doc4"),
        lambda: store.read("heidi", "doc6"),
        lambda: store.write("heidi", "doc1", "правка стажиста"),
        lambda: store.delete("bob", "doc3"),
        lambda: store.delete("bob", "doc5"),
        lambda: store.read("carol", "doc9"),
        lambda: store.write("dave", "doc12", "бюджет, версія 2"),
        lambda: store.read("erin", "doc16"),
        lambda: store.read("grace", "doc11"),
        lambda: store.read("grace", "doc17"),
        lambda: store.write("frank", "doc15", "кадрова політика, версія 2"),
        lambda: monitor.check("dave", "doc14", R),
    ]
    for operation in operations:
        try:
            operation()
        except PermissionError as error:
            print("відмову перехоплено:", error)
    return len(operations)


def main() -> None:
    policy = build_policy()
    subjects, objects = list(SUBJECTS), list(OBJECTS)

    print("== Політика ==")
    print(f"суб'єктів: {len(policy.subjects)}, об'єктів: {len(policy.objects)}, правил: {len(policy.rules)}")
    for rule in policy.rules:
        print(f"{rule.code}  {rule.permissions.name:<13}{rule.title}")

    print("\n== Таблиця рішень ==")
    show_decisions(policy)

    print("\n== Монітор і журнали ==")
    clock = Clock(datetime(2026, 10, 12, 9, 0), timedelta(minutes=5))
    monitor = ReferenceMonitor(policy, AuditLog(clock))
    store = DocumentStore(monitor, {name: f"вміст {name}" for name in objects}, OperationLog(lambda: clock.now))
    calls = work_day(monitor, store)
    entries = monitor.audit.entries()
    print(f"звернень до монітора: {calls}, записів у реєстраційному журналі: {len(entries)}")
    print(f"дозволів: {sum(e['allowed'] for e in entries)}, відмов: {sum(not e['allowed'] for e in entries)}")
    print("-- реєстраційний журнал --")
    print(monitor.audit.dump())
    print("-- операційний журнал --")
    print(store.oplog.dump())

    print("\n== Детектор аномалій ==")
    detector = VariantDetector(deny_threshold=5, window_seconds=60, run_threshold=5)
    print("звичайна робота:", detector.scan(monitor.audit))

    clock.step = timedelta(seconds=2)
    for obj, action in [("doc19", R), ("doc16", R), ("doc20", R), ("doc15", R), ("doc19", W), ("doc16", W)]:
        monitor.check("erin", obj, action)
    for number in range(1, 9):
        monitor.check("grace", f"doc{number}", R)
    print("після сплеску відмов erin і перебору grace:")
    for alert in detector.scan(monitor.audit):
        print(" ", alert)

    print("-- чутливість до порога серії --")
    review = AuditLog(Clock(datetime(2026, 10, 12, 14, 0), timedelta(minutes=3)))
    review_monitor = ReferenceMonitor(policy, review)
    for number in range(1, 6):
        review_monitor.check("alice", f"doc{number}", R)
    for threshold in (5, 8):
        print(f"alice переглядає doc1–doc5, поріг {threshold}:",
              VariantDetector(run_threshold=threshold).scan(review))
    print("журнал із перебором grace, поріг 8:",
          [a for a in VariantDetector(run_threshold=8).scan(monitor.audit) if a.startswith("А3")])

    print("\n== Запити ==")
    for obj, action in [("doc1", R), ("doc3", W), ("doc4", D), ("doc17", R)]:
        print(f"хто має {action.name} до {obj}:", subjects_with_access(policy, subjects, obj, action))
    for subject, action in [("alice", R), ("alice", W), ("heidi", R), ("erin", R), ("grace", R), ("bob", D)]:
        print(f"до чого {subject} має {action.name}:", objects_accessible_by(policy, subject, objects, action))
    pairs = mismatches = 0
    for action in (R, W, D):
        for obj in objects:
            who = subjects_with_access(policy, subjects, obj, action)
            for subject in subjects:
                pairs += 1
                mismatches += (subject in who) != (obj in objects_accessible_by(policy, subject, objects, action))
    print(f"перевірено трійок «суб'єкт — об'єкт — дія»: {pairs}, розбіжностей між запитами: {mismatches}")


if __name__ == "__main__":
    main()
