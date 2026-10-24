#!/usr/bin/env python3
"""Validate output.csv against the participant-facing output contract."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STEP_SCHEMA = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT"),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
}
STEP_FIELDS = {"step_no", "phase", "system_id", "resource_id",
               "operation", "state", "evidence_id"}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def main() -> int:
    requests = read_csv(ROOT / "dataset" / "deletion_requests.csv")
    output_path = ROOT / "output.csv"
    with output_path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ["case_id", "deletion_status", "steps_json"]:
            raise AssertionError(f"Unexpected output columns: {reader.fieldnames!r}")
        output = list(reader)

    expected_ids = sorted(row["case_id"] for row in requests)
    actual_ids = [row["case_id"] for row in output]
    if len(output) != len(requests) or actual_ids != expected_ids:
        raise AssertionError("output.csv must contain every request exactly once in case_id order")
    request_by_id = {row["case_id"]: row for row in requests}
    sources: dict[str, datetime | None] = {}
    for row in read_csv(ROOT / "dataset" / "evidence_files.csv"):
        sources[row["file_id"]] = parse_time(row.get("captured_at"))
    for row in read_csv(ROOT / "dataset" / "system_activity.csv"):
        sources[row["activity_id"]] = parse_time(row.get("event_time"))
    for row in read_csv(ROOT / "dataset" / "user_audit_log.csv"):
        sources[row["audit_id"]] = parse_time(row.get("event_time"))

    counts: Counter[str] = Counter()
    step_count = 0
    for row in output:
        status = row["deletion_status"]
        if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            raise AssertionError(f"{row['case_id']}: invalid deletion_status {status!r}")
        counts[status] += 1
        steps = json.loads(row["steps_json"])
        if not isinstance(steps, list):
            raise AssertionError(f"{row['case_id']}: steps_json is not an array")
        step_count += len(steps)
        if [step.get("step_no") for step in steps] != list(range(1, len(steps) + 1)):
            raise AssertionError(f"{row['case_id']}: step_no values are not consecutive")
        ranks: list[int] = []
        for step in steps:
            if set(step) != STEP_FIELDS:
                raise AssertionError(f"{row['case_id']}: step fields do not match the contract")
            operation = step["operation"]
            if operation not in STEP_SCHEMA:
                raise AssertionError(f"{row['case_id']}: invalid operation {operation!r}")
            phase, state = STEP_SCHEMA[operation]
            if step["phase"] != phase or step["state"] != state:
                raise AssertionError(f"{row['case_id']}: invalid phase/state for {operation}")
            ranks.append(PHASE_ORDER[phase])
            evidence_id = step["evidence_id"]
            if phase == "FINDING" and not evidence_id:
                raise AssertionError(f"{row['case_id']}: finding has no evidence citation")
            if status == "COMPLETE" and (phase != "VERIFICATION" or not evidence_id):
                raise AssertionError(f"{row['case_id']}: COMPLETE requires cited verification steps only")
            if status == "INCOMPLETE" and phase != "FINDING" and evidence_id:
                raise AssertionError(f"{row['case_id']}: future work must have an empty evidence_id")
            if evidence_id:
                if evidence_id not in sources:
                    raise AssertionError(f"{row['case_id']}: unknown evidence citation {evidence_id!r}")
                source_time = sources[evidence_id]
                cutoff = parse_time(request_by_id[row["case_id"]].get("audit_at"))
                if source_time is not None and cutoff is not None and source_time > cutoff:
                    raise AssertionError(f"{row['case_id']}: evidence citation is after audit_at")
        if ranks != sorted(ranks):
            raise AssertionError(f"{row['case_id']}: phases are out of order")
        if status == "NOT_APPLICABLE" and steps:
            raise AssertionError(f"{row['case_id']}: NOT_APPLICABLE must have [] steps_json")
        if status == "COMPLETE" and not steps:
            raise AssertionError(f"{row['case_id']}: COMPLETE must cite verification evidence")

    if sum(counts.values()) != len(requests):
        raise AssertionError("Output status counts do not total the request count")
    print(f"PASS: {len(output)} rows, {step_count} steps, statuses={dict(counts)}; "
          "schema, ordering, operations, citations, and audit cutoffs are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
