"""Диспетчер доступу за моделлю ABAC із заборонними записами (варіант 12)."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Iterable, Mapping

from accesscontrol.monitor import Decision, Permission, Policy

Attributes = Mapping[str, object]
Condition = Callable[[Attributes, Attributes], bool]


@dataclass(frozen=True)
class Rule:
    code: str
    title: str
    permissions: Permission
    condition: Condition


class VariantPolicy(Policy):
    def __init__(self) -> None:
        self._subjects: dict[str, Attributes] = {}
        self._objects: dict[str, Attributes] = {}
        self._allow: list[Rule] = []
        self._deny: list[Rule] = []
        self._sealed = False

    @property
    def subjects(self) -> Mapping[str, Attributes]:
        return MappingProxyType(self._subjects)

    @property
    def objects(self) -> Mapping[str, Attributes]:
        return MappingProxyType(self._objects)

    @property
    def rules(self) -> tuple[Rule, ...]:
        return tuple(self._deny + self._allow)

    def add_subject(self, name: str, **attributes: object) -> None:
        self._require_open()
        self._subjects[name] = MappingProxyType({"id": name, **attributes})

    def add_object(self, name: str, **attributes: object) -> None:
        self._require_open()
        self._objects[name] = MappingProxyType({"id": name, **attributes})

    def allow(self, code: str, title: str, permissions: Permission, condition: Condition) -> None:
        self._require_open()
        self._allow.append(Rule(code, title, permissions, condition))

    def deny(self, code: str, title: str, permissions: Permission, condition: Condition) -> None:
        self._require_open()
        self._deny.append(Rule(code, title, permissions, condition))

    def seal(self) -> None:
        """Забороняє подальші зміни політики."""
        self._sealed = True

    def _require_open(self) -> None:
        if self._sealed:
            raise RuntimeError("політику запечатано, зміни заборонено")

    def evaluate(self, subject: str, obj: str, action: Permission) -> Decision:
        s = self._subjects.get(subject)
        o = self._objects.get(obj)
        if s is None:
            return Decision(False, "невідомий суб'єкт (safe default)")
        if o is None:
            return Decision(False, "невідомий об'єкт (safe default)")
        if action == Permission.NONE:
            return Decision(False, "порожня дія (safe default)")

        for rule in self._deny:
            if action & rule.permissions and rule.condition(s, o):
                return Decision(False, f"заборона {rule.code}: {rule.title}")

        effective = Permission.NONE
        used: list[str] = []
        for rule in self._allow:
            if rule.condition(s, o):
                effective |= rule.permissions
                if action & rule.permissions:
                    used.append(rule.code)
        if action & effective == action:
            return Decision(True, "надано: " + ", ".join(used))
        return Decision(False, "явного дозволу немає (safe default)")


def objects_accessible_by(policy: Policy, subject: str, objects: Iterable[str], action: Permission) -> list[str]:
    return [o for o in objects if policy.evaluate(subject, o, action).allowed]


# суб'єкт: (підрозділ, посада, рівень допуску, стан)
SUBJECTS = {
    "alice": ("dev", "engineer", 2, "active"),
    "bob": ("dev", "lead", 3, "active"),
    "heidi": ("dev", "intern", 1, "active"),
    "carol": ("finance", "accountant", 2, "active"),
    "dave": ("finance", "manager", 3, "active"),
    "erin": ("hr", "specialist", 2, "suspended"),
    "frank": ("hr", "manager", 3, "active"),
    "grace": ("audit", "auditor", 3, "active"),
}

# об'єкт: (підрозділ, тип, гриф, власник, юридична фіксація)
OBJECTS = {
    "doc1": ("dev", "spec", 1, "alice", False),
    "doc2": ("dev", "spec", 2, "alice", False),
    "doc3": ("dev", "design", 2, "bob", True),
    "doc4": ("dev", "design", 3, "bob", False),
    "doc5": ("dev", "report", 2, "alice", False),
    "doc6": ("dev", "guide", 1, "heidi", False),
    "doc7": ("dev", "roadmap", 3, "bob", False),
    "doc8": ("finance", "report", 1, "carol", False),
    "doc9": ("finance", "invoice", 2, "carol", False),
    "doc10": ("finance", "invoice", 2, "carol", False),
    "doc11": ("finance", "budget", 3, "dave", False),
    "doc12": ("finance", "budget", 3, "dave", True),
    "doc13": ("finance", "report", 2, "dave", False),
    "doc14": ("finance", "payroll", 3, "dave", False),
    "doc15": ("hr", "policy", 1, "frank", False),
    "doc16": ("hr", "policy", 2, "erin", False),
    "doc17": ("hr", "personal", 3, "frank", False),
    "doc18": ("hr", "personal", 3, "frank", False),
    "doc19": ("hr", "contract", 2, "erin", False),
    "doc20": ("hr", "vacancy", 1, "erin", False),
    "doc21": ("hr", "personal", 3, "frank", False),
}


def _same_department(s: Attributes, o: Attributes) -> bool:
    return s["department"] == o["department"]


def _cleared(s: Attributes, o: Attributes) -> bool:
    return s["clearance"] >= o["classification"]


def build_policy(with_deny: bool = True) -> VariantPolicy:
    """Політика варіанта: 8 суб'єктів, 21 об'єкт, правила P1–P6 і заборони N1–N3."""
    policy = VariantPolicy()
    for name, (department, position, clearance, status) in SUBJECTS.items():
        policy.add_subject(name, department=department, position=position, clearance=clearance, status=status)
    for name, (department, kind, classification, owner, legal_hold) in OBJECTS.items():
        policy.add_object(name, department=department, kind=kind, classification=classification,
                          owner=owner, legal_hold=legal_hold)

    policy.allow("P1", "читання у своєму підрозділі", Permission.READ,
                 lambda s, o: _same_department(s, o) and _cleared(s, o))
    policy.allow("P2", "редагування у своєму підрозділі", Permission.WRITE,
                 lambda s, o: (_same_department(s, o) and _cleared(s, o)
                               and s["position"] != "intern"))
    policy.allow("P3", "керівник вилучає документи підрозділу", Permission.DELETE,
                 lambda s, o: _same_department(s, o) and s["position"] in ("lead", "manager"))
    policy.allow("P4", "власник документа", Permission.READ | Permission.WRITE,
                 lambda s, o: o["owner"] == s["id"])
    policy.allow("P5", "загальнодоступний документ", Permission.READ,
                 lambda s, o: o["classification"] == 1)
    policy.allow("P6", "аудитор читає документи", Permission.READ,
                 lambda s, o: s["position"] == "auditor")

    if with_deny:
        policy.deny("N1", "юридична фіксація документа", Permission.WRITE | Permission.DELETE,
                    lambda s, o: bool(o["legal_hold"]))
        policy.deny("N2", "обліковий запис призупинено", Permission.ADMIN,
                    lambda s, o: s["status"] == "suspended")
        policy.deny("N3", "аудитор не читає персональні дані", Permission.READ,
                    lambda s, o: s["position"] == "auditor" and o["kind"] == "personal")

    policy.seal()
    return policy
