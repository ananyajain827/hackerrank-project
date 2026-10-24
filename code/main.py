#!/usr/bin/env python3
"""Deterministic, evidence-first deletion audit for Ghost Data Still Exists.

The program uses participant-facing files only. It does not call a model or
trust workflow status fields as evidence. Optional readers for PDFs and images
are enabled when PyMuPDF / Tesseract are installed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sqlite3
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT / "dataset"
DEFAULT_OUTPUT = ROOT / "output.csv"

DELETE_CATEGORIES = {
    "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
    "SUPPORT_ATTACHMENT", "USER_EXPORT", "MARKETING_PROFILE",
}
REDACT_CATEGORIES = {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}
ANONYMIZE_CATEGORIES = {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}
RETAIN_CATEGORIES = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}

FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}
REMEDIATION_ORDER = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}
VERIFICATION_ORDER = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}

SYSTEM_ALIASES = {
    "account_replication_cluster": "account_service",
    "account_failover_replica": "account_service",
    "profile_service": "account_service",
    "search_index_service": "search_service",
    "email_delivery_service": "email_delivery_service",
    "object_store": "export_service",
    "object_storage": "export_service",
    "archive_service": "backup_service",
    "legal_service": "legal_service",
    "integration_management_service": "integration_service",
}

SYSTEM_BY_PREFIX = {
    "account": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "support": "support_platform",
    "export": "export_service",
    "data_flow": "integration_service",
    "connector": "integration_service",
    "backup": "backup_service",
    "audit_record": "security_service",
    "tombstone": "identity_service",
    "marketing": "marketing_platform",
    "cache": "cache_service",
    "email_delivery": "email_delivery_service",
}

PII_KEYS = {
    "email", "owner_email", "customer_email", "requester_email", "subject_email",
    "phone", "owner_phone", "customer_phone", "requester_phone", "subject_phone",
    "email_hash", "name", "full_name", "display_name", "requester_name",
    "customer_name", "subject_name",
}
LINK_KEYS = {
    "user_id", "customer_reference", "subject_reference", "subject_selector",
    "user_reference", "customer_id", "owner_user_id", "user_reference_id",
}
TIME_KEYS = {
    "observed_at", "captured_at", "recorded_at", "event_time", "updated_at",
    "created_at", "indexed_at", "last_seen_at", "checked_at",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def time_text(value: datetime | None) -> str:
    if not value:
        return ""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def norm(value: Any) -> str:
    return str(value).strip().casefold() if value is not None else ""


def phone_digits(value: Any) -> str:
    return re.sub(r"\D", "", str(value or ""))


def scalar_fields(value: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from scalar_fields(child, path)
    elif isinstance(value, list):
        for child in value:
            yield from scalar_fields(child, prefix)
    elif value is not None and not isinstance(value, (bool, int, float)):
        yield prefix.split(".")[-1].casefold(), str(value)
    elif isinstance(value, (bool, int, float)):
        yield prefix.split(".")[-1].casefold(), str(value)


def flat_dict(value: Any) -> dict[str, list[str]]:
    result: dict[str, list[str]] = defaultdict(list)
    for key, item in scalar_fields(value):
        result[key].append(item)
    return dict(result)


def nonempty(values: Iterable[str]) -> list[str]:
    return [x for x in values if norm(x) not in {"", "null", "none", "nan"}]


def parse_bool(value: Any) -> bool | None:
    value = norm(value)
    if value in {"true", "1", "yes", "enabled", "active"}:
        return True
    if value in {"false", "0", "no", "disabled", "inactive"}:
        return False
    return None


def first(values: dict[str, list[str]], *keys: str) -> str:
    for key in keys:
        items = nonempty(values.get(key, []))
        if items:
            return items[-1]
    return ""


def system_name(value: str, resource_id: str = "") -> str:
    value = norm(value).replace(" ", "_")
    if value in SYSTEM_ALIASES:
        value = SYSTEM_ALIASES[value]
    if value in {"account_service", "search_service", "analytics_platform", "support_platform",
                 "export_service", "integration_service", "backup_service", "security_service",
                 "identity_service", "marketing_platform", "cache_service", "email_delivery_service",
                 "legal_service"}:
        return value
    prefix = next((p for p in sorted(SYSTEM_BY_PREFIX, key=len, reverse=True)
                   if resource_id.casefold().startswith(p + "_")), "")
    return SYSTEM_BY_PREFIX.get(prefix, value or SYSTEM_BY_PREFIX.get(prefix, "unknown_service"))


def infer_category(values: dict[str, list[str]], system: str, resource_id: str, hint: str = "") -> str:
    text = " ".join([hint, system, resource_id] + [" ".join(v) for v in values.values()]).casefold()
    rules = [
        (r"tombstone|deleted_customer_references|account_tombstone", "ACCOUNT_TOMBSTONE"),
        (r"security_audit|audit_record|security_audit_log", "SECURITY_AUDIT_LOG"),
        (r"legal_hold|legal_retention|disputed_orders|tax_record", "LEGAL_HOLD_RECORD"),
        (r"backup|restore_entry|backup_archive|archive_path", "BACKUP_ARCHIVE"),
        (r"connector|data_flow|subscription|continuous_sync", "DATA_FLOW"),
        (r"contact_lookup|contact_query", "SECONDARY_IDENTIFIER"),
        (r"analytics_profile|analytics_platform|analytics_report", "ANALYTICS_PROFILE"),
        (r"product_telemetry|telemetry", "PRODUCT_TELEMETRY"),
        (r"support_attachment|attachment", "SUPPORT_ATTACHMENT"),
        (r"support_message|support_record|support_platform|support_ticket", "SUPPORT_MESSAGE"),
        (r"search_document|search_index|search_service", "SEARCH_INDEX_ENTRY"),
        (r"customer_export|user_export|export_job", "USER_EXPORT"),
        (r"marketing_profile|marketing_platform", "MARKETING_PROFILE"),
        (r"email_delivery|delivery_log", "EMAIL_DELIVERY_LOG"),
        (r"cache_entry|cache_service", "CACHE_ENTRY"),
        (r"secondary_identifier|identity_alias", "SECONDARY_IDENTIFIER"),
        (r"customer_profile|user_profile|account_service", "USER_PROFILE"),
    ]
    for pattern, category in rules:
        if re.search(pattern, text):
            return category
    prefix = next((p for p in sorted(("audit_record", "data_flow", "email_delivery", "tombstone",
                                      "account", "search", "analytics", "support", "export",
                                      "backup", "marketing", "cache"), key=len, reverse=True)
                   if resource_id.casefold().startswith(p + "_")), "")
    return {
        "account": "USER_PROFILE", "search": "SEARCH_INDEX_ENTRY", "analytics": "ANALYTICS_PROFILE",
        "support": "SUPPORT_MESSAGE", "export": "USER_EXPORT", "backup": "BACKUP_ARCHIVE",
        "audit": "SECURITY_AUDIT_LOG", "tombstone": "ACCOUNT_TOMBSTONE", "data": "DATA_FLOW",
        "marketing": "MARKETING_PROFILE", "cache": "CACHE_ENTRY", "email": "EMAIL_DELIVERY_LOG",
    }.get(prefix, "UNKNOWN")


def system_from_context(context: dict[str, Any], values: dict[str, list[str]], resource_id: str) -> str:
    for key in ("data_store", "system", "service", "origin_system", "source_system", "target_system"):
        candidate = context.get(key)
        if candidate:
            return system_name(str(candidate), resource_id)
    for key in ("data_store", "system", "service", "origin_system", "source_system", "target_system"):
        candidate = first(values, key)
        if candidate:
            return system_name(candidate, resource_id)
    return system_name("", resource_id)


@dataclass
class Observation:
    evidence_id: str
    captured_at: datetime
    observed_at: datetime
    system_id: str
    resource_id: str
    category: str
    source_slot: str
    fields: dict[str, list[str]] = field(default_factory=dict)
    raw_text: str = ""
    present: bool | None = None
    enabled: bool | None = None
    restore_allowed: bool | None = None
    related_ids: set[str] = field(default_factory=set)

    @property
    def key(self) -> tuple[str, str]:
        return self.system_id, self.resource_id

    def values(self) -> list[str]:
        return [v for items in self.fields.values() for v in items]


@dataclass
class Subject:
    user_id: str
    aliases: set[str]
    emails: set[str]
    phones: set[str]
    hashes: set[str]
    names: set[str]


class Auditor:
    def __init__(self, dataset: Path):
        self.dataset = dataset
        self.manifest = read_csv(dataset / "evidence_files.csv")
        self.identities = read_csv(dataset / "user_identities.csv")
        self.audit_log = read_csv(dataset / "user_audit_log.csv")
        self.activity = read_csv(dataset / "system_activity.csv")
        self.sql_account_snapshots: list[tuple[str, datetime, str, set[str]]] = []
        self.observations = self._load_observations()

    def _add_observation(
        self, output: list[Observation], evidence_id: str, captured: datetime,
        observed: datetime | None, system: str, resource: str, category_hint: str,
        source_slot: str, item: Any, present: bool | None = None,
        raw_text: str = "", explicit_enabled: bool | None = None,
        explicit_restore: bool | None = None,
    ) -> None:
        if not resource:
            return
        fields = flat_dict(item)
        context_hint = category_hint + " " + source_slot
        category = infer_category(fields, system, resource, context_hint)
        observed_at = observed or captured
        if present is None:
            status = first(fields, "status_code", "http_status", "rows", "total_hits", "result", "state", "status", "record_status")
            s = norm(status)
            if s in {"404", "0", "not_found", "not found", "not_found", "no_hit", "miss", "absent", "false"}:
                present = False
            elif s in {"200", "1", "found", "hit", "present", "success"}:
                present = True
            elif "rows" in fields and nonempty(fields["rows"]):
                try:
                    present = int(float(fields["rows"][-1])) > 0
                except ValueError:
                    pass
            elif "profile" in fields and not nonempty(fields["profile"]):
                # Nested null profiles are still a reliable 404-style absence.
                present = False
            elif category not in {"DATA_FLOW"} and any(k in fields for k in ("resource_id", "record_json")):
                present = True
        enabled_text = first(fields, "enabled", "active", "is_enabled")
        enabled = explicit_enabled if explicit_enabled is not None else parse_bool(enabled_text)
        restore_text = first(fields, "restore_allowed", "restore_access", "can_restore")
        restore_allowed = explicit_restore if explicit_restore is not None else parse_bool(restore_text)
        related = set()
        for key, vals in fields.items():
            if key.endswith("_resource_id") or key in {"source_resource", "origin_resource"}:
                related.update(x for x in vals if x and x != resource)
        output.append(Observation(
            evidence_id=evidence_id, captured_at=captured, observed_at=observed_at,
            system_id=system_name(system, resource), resource_id=resource,
            category=category, source_slot=source_slot, fields=fields,
            raw_text=raw_text, present=present, enabled=enabled,
            restore_allowed=restore_allowed, related_ids=related,
        ))

    def _json_observations(self, file_id: str, captured: datetime, data: Any) -> list[Observation]:
        result: list[Observation] = []

        def walk(node: Any, context: dict[str, Any], path: tuple[str, ...]) -> None:
            if isinstance(node, dict):
                current = dict(context)
                for key in ("data_store", "system", "service", "origin_system", "source_system", "target_system", "collection", "record_type", "data_category"):
                    if key in node and isinstance(node[key], (str, int)):
                        current[key] = str(node[key])
                observed = None
                for key in TIME_KEYS:
                    if node.get(key):
                        observed = parse_time(node[key])
                        if observed:
                            break
                if "resource_id" in node:
                    rid = str(node.get("resource_id") or "")
                    system = system_from_context(current, flat_dict(node), rid)
                    category_hint = " ".join([str(current.get("collection", "")), str(current.get("record_type", "")), ".".join(path)])
                    slot = system + ":" + str(current.get("collection", current.get("record_type", ".".join(path))))
                    self._add_observation(result, file_id, captured, observed, system, rid,
                                          category_hint, slot, node)
                for key, child in node.items():
                    if isinstance(child, (dict, list)):
                        walk(child, current, path + (str(key),))
            elif isinstance(node, list):
                for child in node:
                    walk(child, context, path)

        walk(data, {}, ())
        return result

    def _sql_observations(self, file_id: str, captured: datetime, path: Path) -> list[Observation]:
        result: list[Observation] = []
        connection = sqlite3.connect(":memory:")
        try:
            connection.executescript(path.read_text(encoding="utf-8", errors="replace"))
            tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            for (table,) in tables:
                table_lower = table.casefold()
                quoted = '"' + table.replace('"', '""') + '"'
                cursor = connection.execute(f"SELECT * FROM {quoted}")
                columns = [column[0] for column in cursor.description or []]
                table_rows = cursor.fetchall()
                table_resource_ids: set[str] = set()
                for row in table_rows:
                    item = dict(zip(columns, row))
                    if item.get("record_json"):
                        try:
                            item["record_json"] = json.loads(item["record_json"])
                        except (TypeError, json.JSONDecodeError):
                            pass
                    resource = str(item.get("resource_id") or "")
                    if not resource:
                        continue
                    table_resource_ids.add(resource)
                    system = system_name(str(item.get("origin_system") or ""), resource)
                    if not system or system == "unknown_service":
                        system = system_name("", resource)
                    if "customer_profiles" in table_lower or "account" in table_lower:
                        system = "account_service"
                    elif "search" in table_lower:
                        system = "search_service"
                    elif "analytics" in table_lower or "telemetry" in table_lower:
                        system = "analytics_platform"
                    elif "support" in table_lower:
                        system = "support_platform"
                    elif "export" in table_lower:
                        system = "export_service"
                    elif "connector" in table_lower:
                        system = "integration_service"
                    elif "backup" in table_lower:
                        system = "backup_service"
                    elif "security" in table_lower:
                        system = "security_service"
                    elif "identity" in table_lower or "tombstone" in table_lower:
                        system = "identity_service"
                    hint = table.replace("_", " ")
                    if "failover" in table_lower:
                        location = "failover"
                    elif "replica" in table_lower:
                        location = "replica:" + table_lower
                    elif "primary" in table_lower:
                        location = "primary"
                    else:
                        location = table_lower
                    self._add_observation(result, file_id, captured,
                                          parse_time(item.get("updated_at")), system, resource,
                                          hint, system + ":" + location, item)
                if "customer_profiles" in table_lower or table_lower.startswith("customer_profiles"):
                    if "failover" in table_lower:
                        location = "failover"
                    elif "replica" in table_lower:
                        location = "replica:" + table_lower
                    elif "primary" in table_lower:
                        location = "primary"
                    else:
                        location = table_lower
                    self.sql_account_snapshots.append((file_id, captured,
                                                       "account_service:" + location,
                                                       table_resource_ids))
        except sqlite3.Error as exc:
            print(f"Warning: could not read SQL evidence {path.name}: {exc}", file=sys.stderr)
        finally:
            connection.close()
        return result

    @staticmethod
    def _parse_log_fields(line: str) -> dict[str, list[str]]:
        result: dict[str, list[str]] = defaultdict(list)
        # Some supplied logs are pipe-delimited and keep the event columns
        # positional (timestamp | level | service | trace | event | fields).
        parts = [part.strip() for part in line.split("|")]
        if (len(parts) >= 5 and parse_time(parts[0]) and parts[1].upper() in
                {"TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL"}):
            result["level"].append(parts[1])
            result["service"].append(parts[2])
            result["trace_id"].append(parts[3])
            result["event"].append(parts[4])
            line = " ".join([" ".join(parts[5:])])

        # Capture ordinary and escaped quoted key=value fields. In the cloud
        # export, message="..." contains a second escaped key=value record.
        field_pattern = re.compile(
            r"([A-Za-z_][A-Za-z0-9_]*)=(?:\"((?:\\.|[^\"\\])*)\"|'((?:\\.|[^'\\])*)'|([^\s,]+))"
        )
        for match in field_pattern.finditer(line):
            key = match.group(1).casefold()
            value = next((group for group in match.groups()[1:] if group is not None), "")
            value = value.replace('\\"', '"').replace("\\\\", "\\")
            result[key].append(value)
            if key == "message":
                for nested in field_pattern.finditer(value):
                    nested_key = nested.group(1).casefold()
                    nested_value = next((group for group in nested.groups()[1:] if group is not None), "")
                    nested_value = nested_value.replace('\\"', '"').replace("\\\\", "\\")
                    result[nested_key].append(nested_value)
        # JSON-line logs sometimes carry the whole record as a JSON object.
        start = line.find("{")
        if start >= 0:
            try:
                payload = json.loads(line[start:])
                for key, values in flat_dict(payload).items():
                    result[key].extend(values)
            except json.JSONDecodeError:
                pass
        # Several supplied syslog variants place their trace ID as a positional
        # token instead of a named field. Keeping that identifier joins the
        # lookup key on the start line to the resource ID on its completion.
        if not result.get("trace_id") and not result.get("requestid"):
            trace_match = re.search(r"\btr-[A-Za-z0-9-]+\b", line)
            if trace_match:
                result["trace_id"].append(trace_match.group(0))
        return dict(result)

    def _log_observations(self, file_id: str, captured: datetime, path: Path) -> list[Observation]:
        result: list[Observation] = []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        parsed_lines: list[tuple[str, dict[str, list[str]]]] = []
        trace_context: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        for line in lines:
            fields = self._parse_log_fields(line)
            parsed_lines.append((line, fields))
            trace = first(fields, "trace_id", "traceid", "trace", "requestid", "correlation_id")
            if trace:
                for key, values in fields.items():
                    trace_context[trace][key].extend(values)
        for line, line_fields in parsed_lines:
            # The handover artifact is a plain-text table rather than key=value
            # log lines. It provides point-in-time readbacks with explicit state.
            parts = [part.strip() for part in line.split("|")]
            table_time = parts[0].lstrip("- ").strip() if parts else ""
            if len(parts) >= 6 and parse_time(table_time) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*_\d+", parts[2]):
                observed = parse_time(table_time)
                system = system_name(parts[1], parts[2])
                state = norm(parts[4])
                fields = {
                    "resource_id": [parts[2]], "record_type": [parts[3]],
                    "result": [parts[4]], "subject_reference": [parts[5]],
                }
                present = state not in {"not_found", "not found", "absent", "missing"}
                enabled = True if state == "active" and "data_flow" in parts[3].casefold() else (
                    False if state in {"disabled", "stopped"} and "data_flow" in parts[3].casefold() else None)
                restore = True if state == "active" and "backup" in parts[3].casefold() else (
                    False if state in {"blocked", "disabled"} and "backup" in parts[3].casefold() else None)
                self._add_observation(result, file_id, captured, observed, system, parts[2],
                                      parts[3], system + ":readback", fields,
                                      present=present, raw_text=line,
                                      explicit_enabled=enabled, explicit_restore=restore)
                continue
            fields = dict(line_fields)
            trace = first(fields, "trace_id", "traceid", "trace", "requestid", "correlation_id")
            if trace and trace in trace_context:
                merged: dict[str, list[str]] = defaultdict(list)
                for key, values in trace_context[trace].items():
                    merged[key].extend(values)
                for key, values in fields.items():
                    merged[key].extend(values)
                fields = dict(merged)
            rid = first(line_fields, "resource_id", "resource", "target_resource")
            if not rid:
                continue
            observed = parse_time(line[:30].split()[0])
            event = norm(first(line_fields, "event", "event_type", "operation", "message"))
            if any(ending in event for ending in ("started", "_start", "export_started", "batch_started")):
                continue
            direct_state_event = any(token in event for token in (
                "connector_heartbeat", "restore_candidate_evaluated", "restore_policy_check_completed",
                "data_flow_state", "restore_access_state", "message_pii_scan", "analytics_identity_scan",
            ))
            if ("_completed" not in event and "completed" not in event and "_read" not in event
                    and "lookup" not in event and "contact_query" not in event and not direct_state_event):
                # General operational events are claims. The completed readback
                # records below are the evidence observations this auditor uses.
                continue
            system_raw = first(fields, "service", "system", "target_system", "origin_system")
            system = system_name(system_raw, rid)
            category_hint = " ".join([event, path.name])
            # Readback lines are direct state evidence. Do not treat ordinary
            # delete/sync worker results as a current readback.
            if any(x in event for x in ("profile_lookup", "index_query", "support_ticket_read", "support_record_read", "contact_query", "analytics_profile_read", "contact_lookup", "connector_config_read", "restore_policy_read", "audit_record_read", "record_lookup", "profile_read", "tombstone_read", "export_job_read", "export_metadata_read")) or direct_state_event:
                status = first(fields, "http_status", "status_code", "rows", "total_hits", "result")
                s = norm(status)
                present: bool | None = None
                if s in {"404", "0", "not_found", "no_hit", "not found", "not_found"}:
                    present = False
                elif s in {"200", "1", "found", "hit", "success"}:
                    present = True
                if "profile_lookup" in event and s.isdigit():
                    present = int(s) == 200
                if "rows" in fields and nonempty(fields["rows"]):
                    try:
                        present = int(float(fields["rows"][-1])) > 0
                    except ValueError:
                        pass
                if "restore_candidate_evaluated" in event:
                    eligible = parse_bool(first(fields, "eligible"))
                    blocked = parse_bool(first(fields, "deletion_block", "restore_blocked"))
                    if eligible is not None:
                        present = eligible
                    if blocked is not None:
                        self._add_observation(result, file_id, captured, observed, system, rid,
                                              category_hint, system + ":readback", fields,
                                              present=present, raw_text=line,
                                              explicit_restore=(eligible and not blocked))
                        continue
                    if eligible is not None:
                        fields["restore_allowed"] = ["true" if eligible else "false"]
                self._add_observation(result, file_id, captured, observed, system, rid,
                                      category_hint, system + ":readback", fields,
                                      present=present, raw_text=line,
                                      explicit_enabled=parse_bool(first(fields, "enabled")) if "connector_heartbeat" in event else None,
                                      explicit_restore=parse_bool(first(fields, "restore_allowed")) if "restore_policy" in event else None)
        return result

    def _pdf_observations(self, file_id: str, captured: datetime, path: Path) -> list[Observation]:
        result: list[Observation] = []
        try:
            import fitz  # type: ignore[import-not-found]  # PyMuPDF; optional at runtime
            text = "\n".join(page.get_text() for page in fitz.open(path))
        except Exception:
            return result
        resource_ids = set(re.findall(r"\b(?:account|search|analytics|support|export|backup|audit_record|tombstone|data_flow|marketing|cache|email_delivery)_\d+\b", text, re.I))
        user_ids = set(re.findall(r"\buser_\d+\b", text, re.I))
        emails = set(re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text, re.I))
        for resource in resource_ids:
            sysid = system_name("", resource)
            hint = f"{path.name} {text[:900]}"
            fields: dict[str, list[str]] = {"resource_id": [resource]}
            if user_ids:
                fields["user_id"] = list(user_ids)
            if emails:
                fields["email"] = list(emails)
            self._add_observation(result, file_id, captured, captured, sysid, resource,
                                  hint, sysid + ":document", fields,
                                  present=True, raw_text=text)
        # A retention register can identify a retained order without a service
        # resource prefix. Treat the order id as a policy record only when its
        # subject is explicitly named in the same document.
        if "retain until" in text.casefold() or "retention" in text.casefold():
            for order_id in set(re.findall(r"\bORD-\d+\b", text, re.I)):
                if user_ids:
                    fields = {"resource_id": [order_id], "user_id": list(user_ids)}
                    self._add_observation(result, file_id, captured, captured, "legal_service",
                                          order_id, "legal hold retention register", "legal_service:document",
                                          fields, present=True, raw_text=text)
        return result

    def _image_observations(self, file_id: str, captured: datetime, path: Path) -> list[Observation]:
        # OCR is optional because Tesseract is an operating-system executable.
        # When available, screenshots become ordinary searchable observations.
        try:
            from PIL import Image
            import pytesseract  # type: ignore[import-not-found]
            text = pytesseract.image_to_string(Image.open(path))
        except Exception:
            return []
        result: list[Observation] = []
        resource_ids = set(re.findall(r"\b(?:account|search|analytics|support|export|backup|audit_record|tombstone|data_flow|marketing|cache|email_delivery)_\d+\b", text, re.I))
        user_ids = set(re.findall(r"\buser_\d+\b", text, re.I))
        emails = set(re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text, re.I))
        for resource in resource_ids:
            fields: dict[str, list[str]] = {"resource_id": [resource]}
            if user_ids:
                fields["user_id"] = list(user_ids)
            if emails:
                fields["email"] = list(emails)
            sysid = system_name("", resource)
            self._add_observation(result, file_id, captured, captured, sysid, resource,
                                  path.name + " " + text[:1000], sysid + ":screenshot",
                                  fields, present=True, raw_text=text)
        return result

    def _load_observations(self) -> list[Observation]:
        observations: list[Observation] = []
        for item in self.manifest:
            captured = parse_time(item.get("captured_at"))
            path = (self.dataset / item.get("file_path", "")).resolve()
            try:
                path.relative_to(self.dataset.resolve())
            except ValueError:
                continue
            if not captured or not path.is_file():
                continue
            suffix = path.suffix.casefold()
            if suffix == ".json":
                try:
                    observations.extend(self._json_observations(item["file_id"], captured,
                                                                json.loads(path.read_text(encoding="utf-8-sig"))))
                except (OSError, json.JSONDecodeError):
                    continue
            elif suffix == ".sql":
                observations.extend(self._sql_observations(item["file_id"], captured, path))
            elif suffix in {".log", ".txt"}:
                observations.extend(self._log_observations(item["file_id"], captured, path))
            elif suffix == ".pdf":
                observations.extend(self._pdf_observations(item["file_id"], captured, path))
            elif suffix in {".png", ".jpg", ".jpeg", ".webp"}:
                observations.extend(self._image_observations(item["file_id"], captured, path))
        return observations

    def _candidate_users(self, email: str, audit_at: datetime) -> set[str]:
        target = norm(email)
        candidates: set[str] = set()
        for row in self.identities:
            updated = parse_time(row.get("updated_at"))
            if norm(row.get("email")) == target and (not updated or updated <= audit_at):
                candidates.add(row["user_id"])
        for row in self.audit_log:
            when = parse_time(row.get("event_time"))
            if when and when <= audit_at and norm(row.get("field_name")) == "email" and target in {norm(row.get("old_value")), norm(row.get("new_value"))}:
                candidates.add(row["user_id"])
        return candidates

    def _subject(self, user_id: str, email: str, audit_at: datetime) -> Subject:
        identity = next((r for r in self.identities if r["user_id"] == user_id), {})
        current = {k: identity.get(k, "") for k in ("name", "email", "phone", "email_hash")}
        events = [r for r in self.audit_log if r["user_id"] == user_id]
        # Roll a newer snapshot backwards to the case cutoff using later audit
        # events, then add every historical value recorded by the cutoff.
        snapshot_time = parse_time(identity.get("updated_at"))
        if snapshot_time and snapshot_time > audit_at:
            for event in sorted(events, key=lambda x: x["event_time"], reverse=True):
                when = parse_time(event.get("event_time"))
                field_name = norm(event.get("field_name"))
                if when and when > audit_at and field_name in current:
                    if norm(current[field_name]) == norm(event.get("new_value")):
                        current[field_name] = event.get("old_value", "")
        emails: set[str] = {norm(current.get("email")), norm(email)} - {""}
        phones: set[str] = {phone_digits(current.get("phone"))} - {""}
        hashes: set[str] = {norm(current.get("email_hash"))} - {""}
        names: set[str] = {norm(current.get("name"))} - {""}
        for event in events:
            when = parse_time(event.get("event_time"))
            if not when or when > audit_at:
                continue
            field_name = norm(event.get("field_name"))
            for value in (event.get("old_value", ""), event.get("new_value", "")):
                if not value:
                    continue
                if field_name == "email":
                    emails.add(norm(value))
                elif field_name == "phone":
                    phones.add(phone_digits(value))
                elif field_name in {"email_hash", "email_sha256"}:
                    hashes.add(norm(value))
                elif field_name in {"name", "full_name"}:
                    names.add(norm(value))
        for address in list(emails):
            if address:
                hashes.add(hashlib.sha256(address.encode("utf-8")).hexdigest())
        aliases = {user_id.casefold()}
        aliases.update(emails)
        aliases.update(phones)
        aliases.update(hashes)
        aliases.update(names)
        return Subject(user_id, aliases, emails, phones, hashes, names)

    @staticmethod
    def _authorized(text: str) -> bool:
        value = norm(text)
        negative = (
            r"\bnot\s+(?:a\s+)?request\s+to\s+(?:erase|delete)",
            r"\bnot\s+asking\s+for\s+deletion\b",
            r"\bdo\s+not\s+(?:delete|close|erase)\b",
            r"\bdon't\s+(?:delete|close|erase)\b",
            r"\bwithout\s+(?:removing|deleting)",
            r"\bstill\s+(?:need|use|want|using)\s+(?:the\s+)?account",
            r"\bleave\s+(?:the\s+)?account\s+as\s+it\s+is\b",
            r"\bplease\s+keep\s+the\s+account\b",
            r"\bremove\s+me\s+from\s+marketing\s+lists?\s+only\b",
            r"\bmarketing\s+(?:emails?|lists?|messages?)\s+only\b",
        )
        if any(re.search(p, value) for p in negative):
            return False
        positive = (
            r"\bdelet\w*\b", r"\beras\w*\b", r"\berasure\b",
            r"\bremove\w*.{0,90}\b(?:account|profile|record|search\s+result|personal\s+(?:data|details|information)|contact\s+details|identifier)\b",
            r"\b(?:account|profile|record|search\s+result).{0,90}\bremov\w*\b",
            r"\bclos\w*.{0,60}\baccount\b", r"\baccount.{0,60}\bclos\w*\b",
            r"\b(?:account|profile).{0,80}\b(?:gone|deleted|removed)\b",
            r"\b(?:verify|check|inspect|confirm).{0,100}\b(?:account|profile).{0,60}\b(?:gone|deleted|removed)\b",
            r"elimin\w*", r"borr\w*", r"exclus[aã]o", r"exclu\w*", r"apag\w*",
            r"supprim\w*", r"suppression", r"effac\w*",
            r"削除", r"삭제",
        )
        return any(re.search(p, value) for p in positive)

    @staticmethod
    def _obs_matches(obs: Observation, subject: Subject) -> bool:
        vals = {norm(v) for v in obs.values() if norm(v)}
        if vals & subject.aliases:
            return True
        body = norm(obs.raw_text + " " + " ".join(obs.values()))
        if any(email and email in body for email in subject.emails):
            return True
        if any(digest and digest in body for digest in subject.hashes):
            return True
        # Phone numbers and names only match in complete-field values, which
        # avoids substring collisions in unrelated records.
        for key in PII_KEYS:
            for value in obs.fields.get(key, []):
                if phone_digits(value) in subject.phones and len(phone_digits(value)) >= 8:
                    return True
                if norm(value) in subject.names and norm(value):
                    return True
        return False

    def _activity_links(self, subject: Subject, audit_at: datetime) -> dict[tuple[str, str], list[dict[str, str]]]:
        links: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
        for event in self.activity:
            when = parse_time(event.get("event_time"))
            if not when or when > audit_at:
                continue
            body = norm(" ".join(event.values()))
            if not any(alias and alias in body for alias in subject.aliases):
                continue
            rid = event.get("resource_id", "")
            system = system_name(event.get("target_system", ""), rid)
            if rid:
                links[(system, rid)].append(event)
        return links

    @staticmethod
    def _explicit_pii(obs: Observation, subject: Subject) -> bool:
        for key in PII_KEYS:
            for value in nonempty(obs.fields.get(key, [])):
                if norm(value) in subject.aliases:
                    return True
                if key in {"email", "owner_email", "customer_email", "requester_email", "subject_email"} and "@" in value:
                    if norm(value) in subject.emails:
                        return True
                if "phone" in key and phone_digits(value) in subject.phones and len(phone_digits(value)) >= 8:
                    return True
                if "hash" in key and norm(value) in subject.hashes:
                    return True
                if "name" in key and norm(value) in subject.names:
                    return True
        # Readbacks may put the matched identifiers only in free-form fields.
        body = norm(obs.raw_text + " " + " ".join(obs.values()))
        return any(e and e in body for e in subject.emails | subject.hashes)

    @staticmethod
    def _attributable(obs: Observation, subject: Subject) -> bool:
        if Auditor._explicit_pii(obs, subject):
            return True
        for key in LINK_KEYS:
            if any(norm(v) == norm(subject.user_id) for v in obs.fields.get(key, [])):
                return True
        return False

    @staticmethod
    def _latest_by_slot(observations: list[Observation]) -> list[Observation]:
        grouped: dict[str, list[Observation]] = defaultdict(list)
        for obs in observations:
            grouped[obs.source_slot].append(obs)
        selected = []
        for values in grouped.values():
            values.sort(key=lambda x: (x.observed_at, x.captured_at, x.evidence_id))
            selected.append(values[-1])
        return selected

    @staticmethod
    def _has_sensitive_content(obs: Observation, subject: Subject) -> bool:
        return Auditor._explicit_pii(obs, subject)

    def _case(self, row: dict[str, str]) -> tuple[str, list[dict[str, Any]]]:
        if not self._authorized(row.get("request_text", "")):
            return "NOT_APPLICABLE", []

        audit_at = parse_time(row.get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
        candidates = self._candidate_users(row.get("email", ""), audit_at)
        if not candidates:
            # Retain an email-only subject so evidence linked directly to the
            # request address can still be investigated.
            subject = Subject("", {norm(row.get("email", ""))}, {norm(row.get("email", ""))}, set(), set(), set())
        else:
            # If a historic email was reused, prefer the identity whose email
            # was active nearest to the request timestamp.
            request_at = parse_time(row.get("requested_at")) or audit_at
            scores: list[tuple[datetime, str]] = []
            for user_id in candidates:
                matching_times = [parse_time(i.get("updated_at")) for i in self.identities
                                  if i["user_id"] == user_id and norm(i.get("email")) == norm(row.get("email"))]
                matching_times += [parse_time(a.get("event_time")) for a in self.audit_log
                                   if a["user_id"] == user_id and norm(a.get("field_name")) == "email"
                                   and norm(a.get("old_value")) == norm(row.get("email"))]
                relevant = [x for x in matching_times if x and x <= request_at]
                scores.append((max(relevant, default=datetime.min.replace(tzinfo=timezone.utc)), user_id))
            chosen = max(scores)[1]
            subject = self._subject(chosen, row.get("email", ""), audit_at)

        eligible = [obs for obs in self.observations if obs.captured_at <= audit_at and obs.observed_at <= audit_at]
        direct_keys: set[tuple[str, str]] = {obs.key for obs in eligible if self._obs_matches(obs, subject)}
        activity_links = self._activity_links(subject, audit_at)
        direct_keys.update(activity_links)

        # Evidence can identify a resource before it is redacted or anonymized.
        # Carry that grounded link forward to later snapshots of the same key.
        changed = True
        while changed:
            before = len(direct_keys)
            for obs in eligible:
                if obs.key in direct_keys:
                    for related in obs.related_ids:
                        candidates_for_id = [other.key for other in eligible if other.resource_id == related]
                        direct_keys.update(candidates_for_id)
                elif obs.related_ids & {rid for _, rid in direct_keys}:
                    direct_keys.add(obs.key)
            changed = len(direct_keys) != before

        # The earliest participant-facing seed profiles use a zero-padded
        # account ID matching their user reference. Later accounts require an
        # explicit resource link from participant-visible evidence.
        if subject.user_id and not any(key[0] == "account_service" for key in direct_keys):
            m = re.fullmatch(r"user_(\d+)", subject.user_id, re.I)
            if m:
                number = int(m.group(1))
                candidate = f"account_{number:03d}"
                if number <= 10:
                    direct_keys.add(("account_service", candidate))

        request_at = parse_time(row.get("requested_at")) or audit_at
        current_accounts = {key for key in direct_keys if key[0] == "account_service" and any(
            obs.key == key and obs.observed_at >= request_at for obs in eligible
        )}
        if current_accounts:
            for key in list(direct_keys):
                if key[0] != "account_service" or key in current_accounts:
                    continue
                stable_link = any(obs.key == key and any(
                    norm(value) == norm(subject.user_id)
                    for link_key in LINK_KEYS for value in obs.fields.get(link_key, [])
                ) for obs in eligible)
                if not stable_link:
                    direct_keys.discard(key)

        relevant = [obs for obs in eligible if obs.key in direct_keys]
        # Model table exports as point-in-time snapshots for a known account ID:
        # absence from the latest profile table is evidence-backed absence. This
        # is also how the supplied SQL replica captures expose stale copies.
        account_keys_seen = {key for key in direct_keys if key[0] == "account_service"}
        account_keys_seen.update(obs.key for obs in relevant
                                 if obs.system_id == "account_service" and obs.category == "USER_PROFILE")
        for system, resource in account_keys_seen:
            snapshots_by_slot: dict[str, tuple[str, datetime, set[str]]] = {}
            for file_id, captured, slot, resource_ids in self.sql_account_snapshots:
                if captured <= audit_at:
                    old = snapshots_by_slot.get(slot)
                    if old is None or captured > old[1]:
                        snapshots_by_slot[slot] = (file_id, captured, resource_ids)
            for slot, (file_id, captured, resource_ids) in snapshots_by_slot.items():
                if resource not in resource_ids:
                    relevant.append(Observation(
                        file_id, captured, captured, system, resource, "USER_PROFILE", slot,
                        {"resource_id": [resource], "status": ["absent"]},
                        present=False,
                    ))
        # A later direct readback supersedes an older primary snapshot; retain
        # explicitly captured replicas because they can still drift.
        direct_readbacks: dict[tuple[str, str], datetime] = {}
        for obs in relevant:
            if ":readback" in obs.source_slot:
                direct_readbacks[obs.key] = max(direct_readbacks.get(obs.key, datetime.min.replace(tzinfo=timezone.utc)),
                                                obs.observed_at)
        relevant = [obs for obs in relevant if not (
            obs.key in direct_readbacks and obs.observed_at < direct_readbacks[obs.key]
            and ":replica:" not in obs.source_slot and ":failover" not in obs.source_slot
        )]
        # Keep multiple physical replicas separate while choosing the latest
        # observation within each evidence location.
        latest = self._latest_by_slot(relevant)
        by_key: dict[tuple[str, str], list[Observation]] = defaultdict(list)
        for obs in latest:
            by_key[obs.key].append(obs)

        findings: list[dict[str, Any]] = []
        repairs: list[dict[str, Any]] = []
        required_checks: dict[tuple[str, str, str], dict[str, Any]] = {}
        observed_resources: set[tuple[str, str]] = set()

        for key, locations in by_key.items():
            # A later point-in-time absence at the same system and location
            # supersedes older rows; any remaining live replica is still a
            # violation, so examine each physical location before de-duplicating.
            categories = [o.category for o in locations if o.category != "UNKNOWN"]
            category = categories[-1] if categories else locations[-1].category
            resource_id = key[1]
            primary_system = key[0]
            observed_resources.add(key)
            present_obs = [o for o in locations if o.present is not False]
            if category in {"DATA_FLOW"}:
                active = [o for o in locations if o.enabled is True]
                disabled = [o for o in locations if o.enabled is False]
                if active:
                    obs = max(active, key=lambda x: (x.observed_at, x.captured_at))
                    findings.append(self._step("FINDING", primary_system, resource_id,
                                               "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", obs.evidence_id))
                    repairs.append(self._step("REMEDIATION", primary_system, resource_id,
                                              "DISABLE_DATA_FLOW", "DISABLED", ""))
                    required_checks[(primary_system, resource_id, "VERIFY_DATA_FLOW_DISABLED")] = self._step(
                        "VERIFICATION", primary_system, resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", "")
                elif disabled:
                    obs = max(disabled, key=lambda x: (x.observed_at, x.captured_at))
                    required_checks[(primary_system, resource_id, "VERIFY_DATA_FLOW_DISABLED")] = self._step(
                        "VERIFICATION", primary_system, resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", obs.evidence_id)
                continue
            if category == "BACKUP_ARCHIVE":
                restorable = [o for o in locations if o.restore_allowed is True]
                blocked = [o for o in locations if o.restore_allowed is False]
                if restorable:
                    obs = max(restorable, key=lambda x: (x.observed_at, x.captured_at))
                    findings.append(self._step("FINDING", primary_system, resource_id,
                                               "REPORT_RESTORE_RISK", "ACTIVE", obs.evidence_id))
                    repairs.append(self._step("REMEDIATION", primary_system, resource_id,
                                              "BLOCK_RESTORE", "BLOCKED", ""))
                    required_checks[(primary_system, resource_id, "VERIFY_RESTORE_BLOCKED")] = self._step(
                        "VERIFICATION", primary_system, resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", "")
                elif blocked:
                    obs = max(blocked, key=lambda x: (x.observed_at, x.captured_at))
                    required_checks[(primary_system, resource_id, "VERIFY_RESTORE_BLOCKED")] = self._step(
                        "VERIFICATION", primary_system, resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", obs.evidence_id)
                continue

            if category in DELETE_CATEGORIES:
                if present_obs:
                    obs = max(present_obs, key=lambda x: (x.observed_at, x.captured_at))
                    findings.append(self._step("FINDING", primary_system, resource_id,
                                               "REPORT_REMAINING_RECORD", "PRESENT", obs.evidence_id))
                    repairs.append(self._step("REMEDIATION", primary_system, resource_id,
                                              "DELETE_RECORD", "ABSENT", ""))
                    required_checks[(primary_system, resource_id, "VERIFY_RECORD_ABSENT")] = self._step(
                        "VERIFICATION", primary_system, resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", "")
                else:
                    obs = max(locations, key=lambda x: (x.observed_at, x.captured_at))
                    required_checks[(primary_system, resource_id, "VERIFY_RECORD_ABSENT")] = self._step(
                        "VERIFICATION", primary_system, resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", obs.evidence_id)
                continue

            if category in REDACT_CATEGORIES:
                exposed = [o for o in present_obs if self._has_sensitive_content(o, subject)]
                if exposed:
                    obs = max(exposed, key=lambda x: (x.observed_at, x.captured_at))
                    findings.append(self._step("FINDING", primary_system, resource_id,
                                               "REPORT_EXPOSED_PII", "PRESENT", obs.evidence_id))
                    repairs.append(self._step("REMEDIATION", primary_system, resource_id,
                                              "REDACT_RECORD", "REDACTED", ""))
                    required_checks[(primary_system, resource_id, "VERIFY_RECORD_REDACTED")] = self._step(
                        "VERIFICATION", primary_system, resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", "")
                elif present_obs:
                    obs = max(present_obs, key=lambda x: (x.observed_at, x.captured_at))
                    required_checks[(primary_system, resource_id, "VERIFY_RECORD_REDACTED")] = self._step(
                        "VERIFICATION", primary_system, resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", obs.evidence_id)
                continue

            if category in ANONYMIZE_CATEGORIES:
                attributable = [o for o in present_obs if self._attributable(o, subject)]
                if attributable:
                    obs = max(attributable, key=lambda x: (x.observed_at, x.captured_at))
                    findings.append(self._step("FINDING", primary_system, resource_id,
                                               "REPORT_EXPOSED_PII", "PRESENT", obs.evidence_id))
                    repairs.append(self._step("REMEDIATION", primary_system, resource_id,
                                              "ANONYMIZE_RECORD", "ANONYMIZED", ""))
                    required_checks[(primary_system, resource_id, "VERIFY_RECORD_ANONYMIZED")] = self._step(
                        "VERIFICATION", primary_system, resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", "")
                elif present_obs:
                    obs = max(present_obs, key=lambda x: (x.observed_at, x.captured_at))
                    required_checks[(primary_system, resource_id, "VERIFY_RECORD_ANONYMIZED")] = self._step(
                        "VERIFICATION", primary_system, resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", obs.evidence_id)
                continue

            if category in RETAIN_CATEGORIES:
                if present_obs:
                    obs = max(present_obs, key=lambda x: (x.observed_at, x.captured_at))
                    required_checks[(primary_system, resource_id, "VERIFY_RECORD_PRESENT")] = self._step(
                        "VERIFICATION", primary_system, resource_id, "VERIFY_RECORD_PRESENT", "PRESENT", obs.evidence_id)

        # Account removal is always a required final condition. If a linked
        # account was already observed, its step is in the checks above. If the
        # account is absent from a targeted SQL/readback source, add that proof.
        account_keys = [key for key in direct_keys if key[0] == "account_service"]
        account_keys.extend(key for key in observed_resources if key[0] == "account_service" and key not in account_keys)
        for key in account_keys:
            locations = by_key.get(key, [])
            if not locations:
                continue
            if not any(f.get("resource_id") == key[1] and f.get("system_id") == key[0]
                       for f in findings):
                absent = [o for o in locations if o.present is False]
                if absent:
                    obs = max(absent, key=lambda x: (x.observed_at, x.captured_at))
                    required_checks[(key[0], key[1], "VERIFY_RECORD_ABSENT")] = self._step(
                        "VERIFICATION", key[0], key[1], "VERIFY_RECORD_ABSENT", "ABSENT", obs.evidence_id)

        if findings:
            # Remediation plans need future verification for every changed
            # resource, plus already known retained records and the account.
            for key, locations in by_key.items():
                if key[0] == "account_service" and not any(f.get("resource_id") == key[1] for f in findings):
                    required_checks[(key[0], key[1], "VERIFY_RECORD_ABSENT")] = self._step(
                        "VERIFICATION", key[0], key[1], "VERIFY_RECORD_ABSENT", "ABSENT", "")
                for obs in locations:
                    if obs.category in RETAIN_CATEGORIES and obs.present is not False:
                        required_checks[(obs.system_id, obs.resource_id, "VERIFY_RECORD_PRESENT")] = self._step(
                            "VERIFICATION", obs.system_id, obs.resource_id, "VERIFY_RECORD_PRESENT", "PRESENT", "")
            status = "INCOMPLETE"
            steps = self._ordered(findings, repairs, list(required_checks.values()), incomplete=True)
            return status, steps

        checks = list(required_checks.values())
        account_absence_proven = any(
            step["phase"] == "VERIFICATION" and step["system_id"] == "account_service"
            and step["operation"] == "VERIFY_RECORD_ABSENT" and step["evidence_id"]
            for step in checks
        )
        if checks and account_absence_proven and all(step["evidence_id"] for step in checks):
            steps = self._ordered([], [], checks, incomplete=False)
            return "COMPLETE", steps

        # If no violation is evidenced but the available participant records do
        # not prove a compliant final state, keep the case open and show the
        # verification work required. This avoids claiming deletion on silence.
        if not checks:
            for key in account_keys:
                checks.append(self._step("VERIFICATION", key[0], key[1],
                                         "VERIFY_RECORD_ABSENT", "ABSENT", ""))
            # A participant-facing identity link can name a resource even when
            # no direct state readback survived before audit_at. Keep the case
            # open and emit the appropriate future verification for that ID.
            for key in direct_keys:
                if key[0] == "account_service":
                    operation, state = "VERIFY_RECORD_ABSENT", "ABSENT"
                elif key[0] in {"search_service", "export_service", "marketing_platform", "cache_service"}:
                    operation, state = "VERIFY_RECORD_ABSENT", "ABSENT"
                elif key[0] == "analytics_platform":
                    operation, state = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
                elif key[0] == "integration_service":
                    operation, state = "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
                elif key[0] == "backup_service":
                    operation, state = "VERIFY_RESTORE_BLOCKED", "BLOCKED"
                elif key[0] == "security_service":
                    operation, state = "VERIFY_RECORD_PRESENT", "PRESENT"
                elif key[0] == "identity_service" or key[0] == "email_delivery_service":
                    operation, state = "VERIFY_RECORD_REDACTED", "REDACTED"
                elif key[0] == "support_platform":
                    activity_details = " ".join(x.get("details", "") for x in activity_links.get(key, [] )).casefold()
                    if "attachment" in activity_details and "belongs only" in activity_details:
                        operation, state = "VERIFY_RECORD_ABSENT", "ABSENT"
                    elif "attachment" in activity_details:
                        operation, state = "VERIFY_RECORD_ABSENT", "ABSENT"
                    else:
                        operation, state = "VERIFY_RECORD_REDACTED", "REDACTED"
                else:
                    continue
                if not any(s["system_id"] == key[0] and s["resource_id"] == key[1]
                           and s["operation"] == operation for s in checks):
                    checks.append(self._step("VERIFICATION", key[0], key[1], operation, state, ""))
        elif not account_absence_proven:
            # A confirmed audit log, redacted message, or anonymous statistic
            # cannot replace the required account-profile absence check.
            for key in account_keys:
                if not any(step["system_id"] == key[0] and step["resource_id"] == key[1]
                           and step["operation"] == "VERIFY_RECORD_ABSENT" for step in checks):
                    checks.append(self._step("VERIFICATION", key[0], key[1],
                                             "VERIFY_RECORD_ABSENT", "ABSENT", ""))
        if checks:
            status = "INCOMPLETE"
            return status, self._ordered([], [], checks, incomplete=True)
        return "INCOMPLETE", []

    @staticmethod
    def _step(phase: str, system: str, resource: str, operation: str, state: str, evidence: str) -> dict[str, Any]:
        return {
            "step_no": 0,
            "phase": phase,
            "system_id": system,
            "resource_id": resource,
            "operation": operation,
            "state": state,
            "evidence_id": evidence,
        }

    @staticmethod
    def _ordered(findings: list[dict[str, Any]], repairs: list[dict[str, Any]],
                 checks: list[dict[str, Any]], incomplete: bool) -> list[dict[str, Any]]:
        order_map = {"FINDING": FINDING_ORDER, "REMEDIATION": REMEDIATION_ORDER,
                     "VERIFICATION": VERIFICATION_ORDER}
        pieces = []
        if findings:
            deduped_findings: dict[tuple[str, str, str], dict[str, Any]] = {}
            for step in findings:
                key = (step["system_id"], step["resource_id"], step["operation"])
                deduped_findings.setdefault(key, step)
            pieces.append(sorted(deduped_findings.values(), key=lambda s: (
                order_map[s["phase"]][s["operation"]], s["system_id"], s["resource_id"])))
        if repairs:
            deduped_repairs: dict[tuple[str, str, str], dict[str, Any]] = {}
            for step in repairs:
                key = (step["system_id"], step["resource_id"], step["operation"])
                deduped_repairs.setdefault(key, step)
            pieces.append(sorted(deduped_repairs.values(), key=lambda s: (
                order_map[s["phase"]][s["operation"]], s["system_id"], s["resource_id"])))
        if checks:
            deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
            for step in checks:
                if incomplete:
                    step = dict(step)
                    step["evidence_id"] = ""
                key = (step["system_id"], step["resource_id"], step["operation"])
                existing = deduped.get(key)
                # Keep a future check for a remediated item; otherwise retain
                # the evidence-backed completed check.
                if existing is None or (incomplete and not step["evidence_id"]):
                    deduped[key] = step
            pieces.append(sorted(deduped.values(), key=lambda s: (
                order_map[s["phase"]][s["operation"]], s["system_id"], s["resource_id"])))
        result = [step for group in pieces for step in group]
        for number, step in enumerate(result, 1):
            step["step_no"] = number
        return result

    def run(self, requests_path: Path, output_path: Path) -> int:
        requests = read_csv(requests_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        result: list[dict[str, str]] = []
        for row in sorted(requests, key=lambda x: x["case_id"]):
            status, steps = self._case(row)
            result.append({"case_id": row["case_id"], "deletion_status": status,
                           "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
        with output_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["case_id", "deletion_status", "steps_json"],
                                    lineterminator="\n")
            writer.writeheader()
            writer.writerows(result)
        return len(result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET,
                        help="participant-facing dataset directory")
    parser.add_argument("--requests", type=Path, default=None,
                        help="request CSV (defaults to dataset/deletion_requests.csv)")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                        help="output CSV path (defaults to repository-root output.csv)")
    args = parser.parse_args()
    requests_path = args.requests or (args.dataset / "deletion_requests.csv")
    count = Auditor(args.dataset).run(requests_path, args.output)
    print(f"Wrote {count} rows to {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
