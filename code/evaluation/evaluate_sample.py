#!/usr/bin/env python3
"""Compare a prediction CSV with the public sample answer file."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
STEP_FIELDS = FIELDS[1:]


def load_rows(path: Path) -> dict[str, dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return {row["case_id"]: row for row in csv.DictReader(stream)}


def steps(row: dict[str, str]) -> list[dict[str, Any]]:
    value = json.loads(row["steps_json"])
    if not isinstance(value, list):
        raise ValueError(f"{row['case_id']}: steps_json must be a JSON array")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prediction", type=Path, help="CSV produced by code/main.py")
    parser.add_argument("--gold", type=Path, default=ROOT / "dataset" / "sample_output.csv")
    args = parser.parse_args()

    predicted = load_rows(args.prediction)
    gold = load_rows(args.gold)
    if predicted.keys() != gold.keys():
        missing = sorted(gold.keys() - predicted.keys())
        extra = sorted(predicted.keys() - gold.keys())
        raise SystemExit(f"case IDs differ; missing={missing}, extra={extra}")

    status_correct = sum(predicted[key]["deletion_status"] == row["deletion_status"]
                         for key, row in gold.items())
    sequence_correct = 0
    field_correct = field_count = 0
    predicted_step_count = gold_step_count = matched_step_count = 0

    for case_id, expected_row in gold.items():
        actual = steps(predicted[case_id])
        expected = steps(expected_row)
        sequence_correct += actual == expected
        predicted_step_count += len(actual)
        gold_step_count += len(expected)

        actual_counts = Counter(tuple(step.get(field) for field in STEP_FIELDS) for step in actual)
        expected_counts = Counter(tuple(step.get(field) for field in STEP_FIELDS) for step in expected)
        matched_step_count += sum((actual_counts & expected_counts).values())

        for index in range(max(len(actual), len(expected))):
            for field in FIELDS:
                field_count += 1
                if (index < len(actual) and index < len(expected)
                        and actual[index].get(field) == expected[index].get(field)):
                    field_correct += 1

    precision = matched_step_count / predicted_step_count if predicted_step_count else 0.0
    recall = matched_step_count / gold_step_count if gold_step_count else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    print(f"Cases: {len(gold)}")
    print(f"Status accuracy: {status_correct}/{len(gold)} ({status_correct / len(gold):.2%})")
    print(f"Exact sequence accuracy: {sequence_correct}/{len(gold)} ({sequence_correct / len(gold):.2%})")
    print(f"Field accuracy: {field_correct}/{field_count} ({field_correct / field_count:.2%})")
    print(f"Exact-step precision: {matched_step_count}/{predicted_step_count} ({precision:.2%})")
    print(f"Exact-step recall: {matched_step_count}/{gold_step_count} ({recall:.2%})")
    print(f"Exact-step F1: {f1:.2%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
