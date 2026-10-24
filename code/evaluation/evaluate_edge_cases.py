#!/usr/bin/env python3
"""Run focused checks for authorization, identifier matching, and policy rules."""

from __future__ import annotations

import sys
import csv
import json
import shutil
import types
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))

from main import Auditor, Observation, Subject, parse_time  # noqa: E402


def write_csv(path: Path, headers: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=headers, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def synthetic_case(request_text: str, request_email: str, records: list[dict[str, str]],
                   audit_rows: list[dict[str, str]] | None = None,
                   user_id: str = "user_900",
                   identities: list[dict[str, str]] | None = None) -> tuple[str, list[dict[str, object]]]:
    """Run one isolated end-to-end case using a tiny participant-style fixture."""
    with tempfile.TemporaryDirectory(prefix="ghost-audit-edge-") as temporary:
        dataset = Path(temporary)
        evidence_dir = dataset / "evidence"
        evidence_dir.mkdir()
        shutil.copyfile(ROOT / "dataset" / "deletion_rules.csv", dataset / "deletion_rules.csv")
        write_csv(dataset / "evidence_files.csv", ["file_id", "file_path", "origin", "captured_at"], [{
            "file_id": "edge_evidence_01", "file_path": "evidence/state.json",
            "origin": "synthetic participant fixture", "captured_at": "2026-06-01T00:00:00Z",
        }])
        (evidence_dir / "state.json").write_text(json.dumps({"records": records}), encoding="utf-8")
        identity_rows = identities or [{
            "user_id": user_id, "name": "Example Person", "email": "current@example.test",
            "phone": "+1 212 555 0199", "email_hash": "", "updated_at": "2026-02-01T00:00:00Z",
        }]
        write_csv(dataset / "user_identities.csv",
                  ["user_id", "name", "email", "phone", "email_hash", "updated_at"], identity_rows)
        write_csv(dataset / "user_audit_log.csv",
                  ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"],
                  audit_rows or [])
        write_csv(dataset / "system_activity.csv",
                  ["activity_id", "event_time", "event_type", "source_system", "target_system",
                   "resource_id", "reported_result", "details"], [])
        auditor = Auditor(dataset)
        status, steps = auditor._case({
            "case_id": "edge_case", "email": request_email,
            "requested_at": "2026-03-01T00:00:00Z", "audit_at": "2026-06-02T00:00:00Z",
            "request_text": request_text,
        })
        return status, steps


def run_synthetic_cases() -> int:
    absent_account = {
        "resource_id": "account_900", "system": "account_service", "record_type": "USER_PROFILE",
        "user_id": "user_900", "status": "not_found",
    }

    status, steps = synthetic_case(
        "Please send me a copy of all personal data you hold.", "current@example.test", [absent_account])
    assert status == "NOT_APPLICABLE" and steps == []

    historical_email_audit = [{
        "audit_id": "edge_audit_01", "user_id": "user_900", "event_time": "2026-01-15T00:00:00Z",
        "field_name": "email", "old_value": "historic@example.test", "new_value": "current@example.test",
    }]
    stale_search = {
        "resource_id": "search_900", "system": "search_service", "record_type": "search_document",
        "user_id": "user_900", "email": "historic@example.test", "status": "present",
    }
    live_connector = {
        "resource_id": "connector_900", "system": "integration_service", "record_type": "data_flow",
        "user_id": "user_900", "enabled": True, "status": "present",
    }
    status, steps = synthetic_case(
        "Delete my account and personal data.", "historic@example.test",
        [absent_account, stale_search, live_connector], historical_email_audit)
    assert status == "INCOMPLETE"
    assert {step["operation"] for step in steps} >= {
        "REPORT_REMAINING_RECORD", "REPORT_ACTIVE_DATA_FLOW", "DELETE_RECORD",
        "DISABLE_DATA_FLOW", "VERIFY_RECORD_ABSENT", "VERIFY_DATA_FLOW_DISABLED",
    }
    remediation = [step["operation"] for step in steps if step["phase"] == "REMEDIATION"]
    assert remediation.index("DISABLE_DATA_FLOW") < remediation.index("DELETE_RECORD")

    tombstone = {
        "resource_id": "tombstone_900", "system": "identity_service", "record_type": "ACCOUNT_TOMBSTONE",
        "user_id": "user_900", "name": "Example Person", "email": "current@example.test",
        "phone": "+1 212 555 0199", "status": "present",
    }
    status, steps = synthetic_case(
        "Erase my account permanently.", "current@example.test", [absent_account, tombstone])
    assert status == "INCOMPLETE"
    assert any(step["operation"] == "REPORT_EXPOSED_PII" and step["resource_id"] == "tombstone_900"
               for step in steps)
    assert any(step["operation"] == "REDACT_RECORD" and step["resource_id"] == "tombstone_900"
               for step in steps)
    # Dependency order: a linked search copy must be removed before its source profile.
    source_account = {
        "resource_id": "account_900", "system": "account_service", "record_type": "USER_PROFILE",
        "user_id": "user_900", "status": "present",
    }
    dependent_search = {
        "resource_id": "search_900", "system": "search_service", "record_type": "search_document",
        "user_id": "user_900", "status": "present", "source_resource": "account_900",
    }
    status, steps = synthetic_case(
        "Delete my account.", "current@example.test", [source_account, dependent_search])
    assert status == "INCOMPLETE"
    delete_order = [step["resource_id"] for step in steps
                    if step["phase"] == "REMEDIATION" and step["operation"] == "DELETE_RECORD"]
    assert delete_order.index("search_900") < delete_order.index("account_900")

    restorable_backup = {
        "resource_id": "backup_900", "system": "backup_service", "record_type": "BACKUP_ARCHIVE",
        "user_id": "user_900", "restore_allowed": True, "status": "present",
    }
    status, steps = synthetic_case(
        "Delete my account.", "current@example.test",
        [source_account, dependent_search, restorable_backup])
    assert status == "INCOMPLETE"
    remediation = [step["operation"] for step in steps if step["phase"] == "REMEDIATION"]
    assert remediation.index("BLOCK_RESTORE") < remediation.index("DELETE_RECORD")

    unknown_flow = {
        "resource_id": "connector_900", "system": "integration_service", "record_type": "data_flow",
        "user_id": "user_900", "status": "present",
    }
    unknown_backup = {
        "resource_id": "backup_901", "system": "backup_service", "record_type": "BACKUP_ARCHIVE",
        "user_id": "user_900", "status": "present",
    }
    status, steps = synthetic_case(
        "Delete my account.", "current@example.test",
        [absent_account, unknown_flow, unknown_backup])
    assert status == "INCOMPLETE"
    assert not any(step["operation"] in {"REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"}
                   for step in steps)
    assert {step["operation"] for step in steps} >= {
        "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
    }

    # Evidence observed after audit_at must not add a finding or change status.
    future_search = dict(dependent_search, resource_id="search_901", observed_at="2026-06-03T00:00:00Z")
    status, steps = synthetic_case(
        "Delete my account.", "current@example.test", [absent_account, future_search])
    assert status == "COMPLETE"
    assert all(step["resource_id"] != "search_901" for step in steps)

    older_account = dict(absent_account, status="present",
                         observed_at="2026-06-01T01:00:00Z")
    newer_account = dict(absent_account, status="not_found",
                         observed_at="2026-06-01T02:00:00Z")
    status, steps = synthetic_case(
        "Delete my account.", "current@example.test", [older_account, newer_account])
    assert status == "COMPLETE"
    assert any(step["operation"] == "VERIFY_RECORD_ABSENT" and
               step["evidence_id"] == "edge_evidence_01" for step in steps)

    # Ambiguous shared addresses stay unresolved instead of selecting a user by sort order.
    shared_identity = [
        {"user_id": "user_900", "name": "First Person", "email": "current@example.test",
         "phone": "", "email_hash": "", "updated_at": "2026-02-01T00:00:00Z"},
        {"user_id": "user_901", "name": "Second Person", "email": "current@example.test",
         "phone": "", "email_hash": "", "updated_at": "2026-02-01T00:00:00Z"},
    ]
    ambiguous_records = [
        {"resource_id": "account_900", "system": "account_service", "record_type": "USER_PROFILE",
         "user_id": "user_900", "status": "present"},
        {"resource_id": "account_901", "system": "account_service", "record_type": "USER_PROFILE",
         "user_id": "user_901", "status": "not_found"},
    ]
    status, steps = synthetic_case(
        "Delete my account.", "current@example.test", ambiguous_records, identities=shared_identity)
    assert status != "COMPLETE"

    # Do not synthesize account IDs from user numbering when evidence has no link.
    status, steps = synthetic_case(
        "Delete my account.", "current@example.test", [], user_id="user_01")
    assert not any(step["resource_id"] == "account_001" for step in steps)

    return 10


def main() -> int:
    authorization_cases = [
        ("access request", "Tell me what personal information you hold about me.", False),
        ("correction without deletion", "Correct my name without removing any of my records.", False),
        ("explicit English denial", "I am not requesting deletion of my account.", False),
        ("direct negative command", "Do not delete my account.", False),
        ("marketing only", "Remove me from marketing lists only; keep my account active.", False),
        ("instructions only", "How do I delete my account?", False),
        ("English deletion with retention exception", "Delete my account but keep the required security audit record.", True),
        ("French deletion", "Je demande la suppression de mon compte.", True),
        ("Spanish deletion", "Solicito la eliminación permanente de la cuenta.", True),
        ("Portuguese deletion", "Solicito a exclusão permanente da conta.", True),
        ("Japanese deletion", "\u3053\u306e\u30a2\u30ab\u30a6\u30f3\u30c8\u306e\u5b8c\u5168\u306a\u524a\u9664\u3092\u4f9d\u983c\u3057\u307e\u3059", True),
        ("Korean deletion", "\uacc4\uc815\uc758 \uc601\uad6c \uc0ad\uc81c\ub97c \uc694\uccad\ud569\ub2c8\ub2e4", True),
        ("German deletion", "Ich beantrage die L\u00f6schung meines Kontos.", True),
        ("French denial", "Je ne demande pas la suppression de mon compte.", False),
        ("Spanish denial", "No solicito la eliminación de mi cuenta.", False),
        ("Portuguese denial", "Não solicito a exclusão da minha conta.", False),
        ("Japanese denial", "\u3053\u306e\u30a2\u30ab\u30a6\u30f3\u30c8\u306e\u524a\u9664\u3092\u5e0c\u671b\u3057\u307e\u305b\u3093", False),
        ("Korean denial", "\uacc4\uc815 \uc0ad\uc81c\ub97c \uc6d0\ud558\uc9c0 \uc54a\uc2b5\ub2c8\ub2e4", False),
        ("German denial", "Ich m\u00f6chte keine L\u00f6schung meines Kontos.", False),
        ("passive English denial", "I do not want my account deleted.", False),
        ("French verb denial", "Je ne veux pas supprimer mon compte.", False),
        ("Spanish verb denial", "No quiero borrar mi cuenta.", False),
        ("Portuguese verb denial", "N\u00e3o quero excluir minha conta.", False),
        ("German verb denial", "Ich m\u00f6chte mein Konto nicht l\u00f6schen.", False),
        ("Japanese verb denial", "\u3053\u306e\u30a2\u30ab\u30a6\u30f3\u30c8\u3092\u524a\u9664\u3057\u305f\u304f\u3042\u308a\u307e\u305b\u3093", False),
        ("Korean verb denial", "\uacc4\uc815\uc744 \uc0ad\uc81c\ud558\uace0 \uc2f6\uc9c0 \uc54a\uc2b5\ub2c8\ub2e4", False),
        ("Chinese verb denial", "\u6211\u4e0d\u5e0c\u671b\u5220\u9664\u6211\u7684\u8d26\u6237", False),
        ("French direct request", "Je veux supprimer mon compte.", True),
        ("Spanish direct request", "Quiero borrar mi cuenta.", True),
        ("Portuguese direct request", "Quero excluir minha conta.", True),
        ("German direct request", "Ich m\u00f6chte mein Konto l\u00f6schen.", True),
        ("Japanese direct request", "\u30a2\u30ab\u30a6\u30f3\u30c8\u3092\u524a\u9664\u3057\u305f\u3044\u3067\u3059", True),
        ("Korean direct request", "\uacc4\uc815\uc744 \uc0ad\uc81c\ud558\uace0 \uc2f6\uc2b5\ub2c8\ub2e4", True),
        ("Chinese direct request", "\u6211\u5e0c\u671b\u5220\u9664\u6211\u7684\u8d26\u6237", True),
    ]
    for label, text, expected in authorization_cases:
        actual = Auditor._authorized(text)
        if actual != expected:
            raise AssertionError(f"{label}: expected {expected}, got {actual}")

    with (ROOT / "dataset" / "sample_deletion_requests.csv").open(encoding="utf-8-sig", newline="") as stream:
        sample_requests = list(csv.DictReader(stream))
    if not all(Auditor._authorized(row["request_text"]) for row in sample_requests):
        raise AssertionError("a public sample request was incorrectly classified as not applicable")

    subject = Subject("user_01", {"user_01", "abc@example.com"}, {"abc@example.com"},
                      {"1234567890"}, set(), {"noor khalil"})
    assert not Auditor._text_matches_subject("subject_ref=user_010", subject)
    assert Auditor._text_matches_subject("subject_ref=user_01", subject)
    assert not Auditor._text_matches_subject("owner=xabc@example.com", subject)
    assert Auditor._text_matches_subject("owner=abc@example.com", subject)
    assert Auditor._text_matches_subject("Support called the user at 1234567890.", subject)
    message = Observation(
        evidence_id="synthetic", captured_at=parse_time("2026-01-01T00:00:00Z"),
        observed_at=parse_time("2026-01-01T00:00:00Z"), system_id="support_platform",
        resource_id="support_synthetic", category="SUPPORT_MESSAGE", source_slot="synthetic",
        fields={"message_excerpt": ["Noor Khalil confirmed the requested delivery change."]},
    )
    assert Auditor._explicit_pii(message, subject)

    auditor = Auditor(ROOT / "dataset")
    auditor.activity = [{
        "activity_id": "activity_name_phone", "event_time": "2026-09-01T00:00:00Z",
        "target_system": "support_platform", "resource_id": "support_558",
        "details": "Support called Noor Khalil at 1234567890.",
    }]
    auditor.activity_by_word.clear()
    auditor.activity_by_identifier = auditor._index_activity_events()
    activity_links = auditor._activity_links(subject, parse_time("2026-09-02T00:00:00Z"))
    assert ("support_platform", "support_558") in activity_links

    screenshot_text = (
        "resource_id=account_901\nuser_id=user_901\nemail=one@example.test\n\n\n\n"
        "resource_id=search_902\nuser_id=user_902\nemail=two@example.test\n"
    )
    screenshot_observations = auditor._image_observations_from_text(
        "synthetic_image", parse_time("2026-01-01T00:00:00Z"),
        Path("synthetic_screenshot.png"), screenshot_text)
    by_resource = {obs.resource_id: obs for obs in screenshot_observations}
    assert by_resource["account_901"].fields["user_id"] == ["user_901"]
    assert by_resource["search_902"].fields["user_id"] == ["user_902"]
    fake_ocr = types.ModuleType("pytesseract")
    fake_ocr.image_to_string = lambda image: screenshot_text
    try:
        import PIL.Image
    except ImportError:
        pass
    else:
        with patch("PIL.Image.open", return_value=object()), patch.dict(sys.modules, {"pytesseract": fake_ocr}):
            imported_observations = auditor._image_observations(
                "synthetic_image", parse_time("2026-01-01T00:00:00Z"),
                Path("synthetic_screenshot.png"))
        assert {obs.resource_id for obs in imported_observations} == {"account_901", "search_902"}

    expected_actions = {
        "USER_PROFILE": "DELETE", "SUPPORT_MESSAGE": "REDACT",
        "ANALYTICS_PROFILE": "ANONYMIZE", "SECURITY_AUDIT_LOG": "RETAIN",
    }
    for category, action in expected_actions.items():
        if auditor.policy_rules[category]["required_action"].upper() != action:
            raise AssertionError(f"policy action mismatch for {category}")
    cutoff = parse_time("2026-09-15T12:00:00Z")
    def observation(until: str | None) -> list[Observation]:
        fields = {"retention_until": [until]} if until else {}
        return [Observation("synthetic", cutoff, cutoff, "security_service", "audit_record_synthetic",
                            "SECURITY_AUDIT_LOG", "synthetic", fields)]
    assert Auditor._retention_condition("SECURITY_AUDIT_LOG", observation("2026-09-15T12:00:00Z"), cutoff) is True
    assert Auditor._retention_condition("SECURITY_AUDIT_LOG", observation("2026-09-14T12:00:00Z"), cutoff) is False
    assert Auditor._retention_condition("SECURITY_AUDIT_LOG", observation(None), cutoff) is None

    synthetic_cases = run_synthetic_cases()
    print(f"PASS: {len(authorization_cases)} authorization cases; {len(sample_requests)} public requests; "
          f"{synthetic_cases} synthetic end-to-end cases; exact identity matching; screenshot context; "
          "PII in free text; policy loading and retention cutoffs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
