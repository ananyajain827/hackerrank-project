# Evaluation report

## Public sample benchmark

The implementation was run against the 32 requests in `dataset/sample_deletion_requests.csv` and compared with the participant-facing `dataset/sample_output.csv`. This benchmark is separate from the 518-request prediction run; the sample answers are not used by the predictor.

| Metric | Result | Definition |
|---|---:|---|
| Deletion status accuracy | 26/32 (81.25%) | Exact match for `deletion_status` per case |
| Exact sequence accuracy | 15/32 (46.88%) | Exact ordered `steps_json` match per case |
| Field accuracy | 1000/1351 (74.02%) | Seven fields compared by step position; missing or extra positions count as incorrect |
| Exact-step precision | 148/165 (89.70%) | Multiset match on phase, system, resource, operation, state, and evidence ID |
| Exact-step recall | 148/193 (76.68%) | Same exact-step matches divided by expected steps |
| Exact-step F1 | 82.68% | Harmonic mean of exact-step precision and recall |

`python code/evaluation/evaluate_sample.py <prediction.csv>` reproduces these metrics when `<prediction.csv>` is generated with `code/main.py` for the public sample input.

There is no participant-facing answer key for the 518 evaluation requests, so their hidden-label accuracy cannot be measured locally. The submitted `output.csv` contains 518 rows: 56 `COMPLETE`, 452 `INCOMPLETE`, and 10 `NOT_APPLICABLE`, with 2,539 steps total. These are prediction counts, not accuracy scores.

## Additional participant-created evaluation cases

These three cases extend the public sample with policy and temporal conditions that the auditor must handle. They are specification-derived scenarios, not extra labeled records in the supplied dataset.

1. **Access request with deletion-like context.** A user asks for a copy of their data and says they are not asking to close or erase the account. Expected result: `NOT_APPLICABLE` and `steps_json=[]`.
2. **Historical email with a live connector and stale search document.** The request uses an email found in the user's audit history. At `audit_at`, evidence links that identity to an enabled connector and a matching search record. Expected result: `INCOMPLETE`; report both findings, disable the connector before deleting the dependent search record, then include empty-evidence checks for the future disabled and absent states.
3. **Account tombstone with direct identifiers.** The account profile is absent, while a policy-required tombstone still contains the stable user reference plus a name, email, phone, and email hash. Expected result: `INCOMPLETE`; report exposed PII, redact the tombstone while preserving its stable reference, then verify account absence and tombstone redaction.

## Failures found and improvements made

- Initial inspection found `code/main.py` empty in the worktree. It now contains the end-to-end auditor, and the public-sample evaluator is in `code/evaluation/evaluate_sample.py`.
- The first log parser missed event details inside escaped message fields and pipe-separated operational records. The parser now extracts nested fields and positional event columns; this recovered evidence-backed findings and checks in the full run.
- The first output review found authorized incomplete cases with no actionable steps. Log parsing and resource-link handling were improved; the final run emits at least one check or finding for every authorized request.
- Six public sample cases labeled `COMPLETE` remain `INCOMPLETE` in this implementation because the available linked readbacks do not provide a provable account-absence check for the relevant subject. Some identifier-free analytics rows also cannot be safely tied to a person after their subject fields have been removed. The implementation preserves this uncertainty instead of claiming completion or assigning a row from the sample answer file.
- Screenshot OCR is optional. This environment did not have the Tesseract executable available, so image-only evidence may be missed in this run. PDF text extraction worked through the installed PyMuPDF package.

## Output contract review

The final generated file was checked for the exact header, 518 case IDs sorted once each, valid JSON arrays, consecutive step numbers, permitted operations/states, and phase ordering. `NOT_APPLICABLE` rows have empty step arrays; completed-case verification steps cite evidence; future remediation and verification steps for incomplete cases have empty evidence IDs. Evidence citations are drawn from participant-visible sources and filtered by `audit_at`.
