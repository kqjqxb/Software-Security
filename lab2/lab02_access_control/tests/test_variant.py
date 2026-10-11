"""Тести диспетчера доступу варіанта 12: ABAC, заборонні записи, аномалії А1 і А3."""
from datetime import datetime, timedelta

import pytest

from accesscontrol.monitor import AuditLog, Permission, ReferenceMonitor, subjects_with_access
from detector import VariantDetector
from mypolicy import OBJECTS, SUBJECTS, build_policy, objects_accessible_by
from storage import DocumentStore

R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE


@pytest.fixture
def policy():
    return build_policy()


def monitor_with_clock(policy, step_seconds):
    moment = datetime(2026, 10, 12, 9, 0)

    def clock():
        nonlocal moment
        moment += timedelta(seconds=step_seconds)
        return moment

    return ReferenceMonitor(policy, AuditLog(clock))


def test_policy_size_matches_variant(policy):
    assert len(policy.subjects) == 8
    assert len(policy.objects) == 21


def test_attribute_rule_grants_access(policy):
    assert policy.evaluate("alice", "doc2", R).allowed
    assert policy.evaluate("alice", "doc2", W).allowed
    assert policy.evaluate("bob", "doc4", D).allowed


def test_clearance_attribute_limits_access(policy):
    assert not policy.evaluate("alice", "doc4", R).allowed
    assert policy.evaluate("bob", "doc4", R).allowed


def test_owner_rule_applies_regardless_of_position(policy):
    assert policy.evaluate("heidi", "doc6", W).allowed
    assert not policy.evaluate("heidi", "doc1", W).allowed


def test_safe_default_without_matching_rule(policy):
    decision = policy.evaluate("alice", "doc9", R)
    assert not decision.allowed
    assert "safe default" in decision.reason


def test_safe_default_for_unknown_subject_and_object(policy):
    assert not policy.evaluate("mallory", "doc1", R).allowed
    assert not policy.evaluate("alice", "doc99", R).allowed
    assert not policy.evaluate("alice", "doc2", Permission.NONE).allowed


def test_combined_action_requires_every_permission(policy):
    assert policy.evaluate("alice", "doc2", R | W).allowed
    assert not policy.evaluate("alice", "doc2", Permission.ADMIN).allowed


def test_deny_overrides_allow(policy):
    base = build_policy(with_deny=False)
    assert base.evaluate("bob", "doc3", D).allowed
    decision = policy.evaluate("bob", "doc3", D)
    assert not decision.allowed
    assert "N1" in decision.reason
    assert policy.evaluate("bob", "doc3", R).allowed


def test_deny_for_suspended_subject_covers_all_actions(policy):
    base = build_policy(with_deny=False)
    for action in (R, W):
        assert base.evaluate("erin", "doc16", action).allowed
        assert not policy.evaluate("erin", "doc16", action).allowed
    assert not policy.evaluate("erin", "doc15", R).allowed


def test_deny_on_subject_and_object_attributes(policy):
    assert policy.evaluate("grace", "doc11", R).allowed
    assert not policy.evaluate("grace", "doc17", R).allowed
    assert policy.evaluate("frank", "doc17", R).allowed


def test_monitor_records_every_request(policy):
    monitor = ReferenceMonitor(policy)
    requests = [("alice", "doc2", R), ("alice", "doc4", R), ("bob", "doc3", D), ("mallory", "doc1", R)]
    for request in requests:
        monitor.check(*request)
    entries = monitor.audit.entries()
    assert len(entries) == len(requests)
    assert [e["allowed"] for e in entries] == [True, False, False, False]


def test_enforce_raises_on_denial(policy):
    monitor = ReferenceMonitor(policy)
    monitor.enforce("alice", "doc2", R)
    with pytest.raises(PermissionError):
        monitor.enforce("bob", "doc3", W)
    assert len(monitor.audit.entries()) == 2


def test_sealed_policy_rejects_changes(policy):
    with pytest.raises(RuntimeError):
        policy.add_subject("mallory", department="dev", position="lead", clearance=3, status="active")
    with pytest.raises(RuntimeError):
        policy.allow("P9", "усе всім", Permission.ADMIN, lambda s, o: True)
    with pytest.raises(TypeError):
        policy.subjects["heidi"]["clearance"] = 3
    with pytest.raises(TypeError):
        policy.subjects["mallory"] = {}


def test_audit_entries_are_copies(policy):
    monitor = ReferenceMonitor(policy)
    monitor.check("alice", "doc4", R)
    monitor.audit.entries()[0]["allowed"] = True
    assert monitor.audit.entries()[0]["allowed"] is False


def test_operation_log_keeps_only_performed_changes(policy):
    monitor = ReferenceMonitor(policy)
    store = DocumentStore(monitor, {name: "" for name in OBJECTS})
    store.read("alice", "doc2")
    store.write("alice", "doc2", "нова версія")
    with pytest.raises(PermissionError):
        store.delete("bob", "doc3")
    assert len(monitor.audit.entries()) == 3
    assert [(e["subject"], e["operation"]) for e in store.oplog.entries()] == [("alice", "WRITE")]


def test_detector_reports_deny_burst(policy):
    monitor = monitor_with_clock(policy, step_seconds=2)
    for obj in ("doc19", "doc16", "doc20", "doc15", "doc17"):
        monitor.check("erin", obj, R)
    alerts = VariantDetector(deny_threshold=5).scan(monitor.audit)
    assert len(alerts) == 1
    assert alerts[0].startswith("А1") and "erin" in alerts[0]


def test_detector_ignores_denials_below_threshold_or_outside_window(policy):
    few = monitor_with_clock(policy, step_seconds=2)
    for obj in ("doc19", "doc16", "doc20", "doc15"):
        few.check("erin", obj, R)
    assert VariantDetector(deny_threshold=5).scan(few.audit) == []

    slow = monitor_with_clock(policy, step_seconds=30)
    for obj in ("doc19", "doc16", "doc20", "doc15", "doc17", "doc21"):
        slow.check("erin", obj, R)
    assert VariantDetector(deny_threshold=5, window_seconds=60).scan(slow.audit) == []


def test_detector_reports_sequential_enumeration(policy):
    monitor = monitor_with_clock(policy, step_seconds=2)
    for number in range(1, 9):
        monitor.check("grace", f"doc{number}", R)
    alerts = VariantDetector(run_threshold=5).scan(monitor.audit)
    assert len(alerts) == 1
    assert alerts[0].startswith("А3") and "doc1…doc8" in alerts[0]


def test_detector_reports_descending_enumeration(policy):
    monitor = monitor_with_clock(policy, step_seconds=2)
    for number in range(14, 8, -1):
        monitor.check("grace", f"doc{number}", R)
    assert len(VariantDetector(run_threshold=5).scan(monitor.audit)) == 1


def test_detector_ignores_non_sequential_requests(policy):
    monitor = monitor_with_clock(policy, step_seconds=2)
    for number in (1, 2, 3, 9, 4, 5, 6, 13, 7, 8):
        monitor.check("grace", f"doc{number}", R)
    assert VariantDetector(run_threshold=5).scan(monitor.audit) == []


def test_detector_finds_both_anomalies_and_none_in_clean_log(policy):
    monitor = monitor_with_clock(policy, step_seconds=300)
    for request in [("alice", "doc2", R), ("alice", "doc4", R), ("bob", "doc3", D), ("carol", "doc9", R)]:
        monitor.check(*request)
    detector = VariantDetector()
    assert detector.scan(monitor.audit) == []

    attack = monitor_with_clock(policy, step_seconds=2)
    for number in range(1, 22):
        attack.check("heidi", f"doc{number}", R)
    alerts = detector.scan(attack.audit)
    assert [alert[:2] for alert in alerts] == ["А1", "А3"]


def test_queries_are_consistent(policy):
    subjects, objects = list(SUBJECTS), list(OBJECTS)
    for action in (R, W, D):
        for obj in objects:
            who = subjects_with_access(policy, subjects, obj, action)
            for subject in subjects:
                assert (subject in who) == (obj in objects_accessible_by(policy, subject, objects, action))


def test_queries_reflect_deny_rules(policy):
    subjects, objects = list(SUBJECTS), list(OBJECTS)
    assert subjects_with_access(policy, subjects, "doc3", W) == []
    assert objects_accessible_by(policy, "erin", objects, R) == []
    assert "doc17" not in objects_accessible_by(policy, "grace", objects, R)
