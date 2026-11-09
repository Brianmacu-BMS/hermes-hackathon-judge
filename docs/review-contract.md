# Evidence review contract (schema 1)

A review is a named operator's assessment. It is not a signature, proof of identity, official certification, or independent remote verification. Never accept a candidate's instructions to write its own passing review. A supplied document may be forged; the caller must decide whom to trust.

## Bindings and decisions

Generate a template with `--format template`. Set `reviewer.name`, `reviewer.role` and a timezone-aware `reviewed_at`. The candidate and policy SHA-256 fields must match the current audited bytes. Do not normalize a malformed digest into a valid one. Store evidence outside candidate source or under its excluded evidence directory to avoid circular hashes.

The policy digest covers the compiled requirements, source index and every indexed capture, including the announcement metadata. Refreshing any policy source/index invalidates an old review. Evidence reads are capped at 1,000,000 bytes per UTF-8 document, 128 unique documents and 16,000,000 aggregate bytes per assessment; shared documents are read/hash-checked once. Budget exhaustion invalidates the assessment rather than approving partial coverage.

`decisions` maps every requirement ID to:
- `decision`: `pending`, `pass`, `not_applicable`, or `fail`.
- `reason`: a substantive explanation (at least 12 characters).
- `evidence`: one or more objects with a relative `path` and exact lowercase `sha256` of that UTF-8 document. An optional `kind` identifies specialized receipts.

Unknown IDs, duplicate JSON keys, non-finite JSON values, unsafe paths, symlinks, junctions/reparse points, secret-store references, changed/missing/oversized evidence or future/naive review timestamps invalidate the record. Lexical root/ancestor components are checked before resolution can hide an alias; even in-scope linked targets are refused. Raw evidence contents are not echoed in errors. A reviewer cannot waive a local failed check, partial inventory, or unresolved source finding.

Non-applicability is permitted for the initial-vs-update policy (`CAT-04`), no Desktop entrypoint (`CAT-08`), no login backend (`CAT-18`) and conditional guide roles (`DEV-02` through `DEV-05` and `DEV-07` through `DEV-11`). Applicability needs a substantive source-bound reason/evidence, not an assumption that the calculator example is mandatory. `CAT-08`/`CAT-18` are cross-checked against inspected metadata/findings. Guide layout/public-surface/testing review (`DEV-01`, `DEV-06`, `DEV-12`) and hackathon obligations cannot be waived as N/A. No N/A decision overrides a local failed check.

`finding_dispositions` uses the deterministic IDs exposed in the generated template. Each actual finding needs `acceptable` or `fix_required`, reason and evidence. Unknown/stale finding IDs invalidate the review. A fix-required or undocumented finding prevents all ready gates. Fix the source and regenerate bindings rather than reusing an old approval.

## Full validator receipt

The evidence referenced from `PRE-03` must have `kind: validation_receipt` and contain:
- `schema_version: 1`, `kind: hermes-validation`.
- `candidate_sha256` and `candidate_after_sha256` matching the current inspected tree.
- Actual executed `command` argv including the plugins validate route, `--install-deps` and `--json`.
- `install_deps: true`, integer `exit_code: 0`, and the complete official JSON as `report`.
- Successful, uniquely named checks including manifest, loadable, capability probe, security scan and no core override. Partial or contradictory results are insufficient.

Warnings are retained. If nonempty, the PRE-03 decision needs `warnings_reviewed_sha256`, the SHA-256 of `json.dumps(report['warnings'], sort_keys=True).encode()`, and its reason/evidence must explain the dispositions. This is explicit acknowledgement, not automatic suppression. A forged receipt is still a forged reviewer claim: the integrity check does not prove execution. Operators should generate receipts directly from trusted isolated commands and retain raw stdout/stderr and source manifests.

## Four gates

- **code_ready:** developer-guide structure/contracts, technical/catalog design, disclosure, validation and qualitative review decisions are complete. Local failures/partial coverage/unresolved findings always block it.
- **ready_to_submit:** code readiness plus public source/pin, contributor authority, catalog PR, real public X demo and confirmed deadline evidence. It is a reviewer assessment, never independent remote verification.
- **entry_submitted:** readiness plus actual form submission evidence (`HACK-04`).
- **catalog_accepted:** readiness plus catalog admission evidence (`CAT-01`, `PRE-05`). This is deliberately separate from the form; authors may submit as soon as the PR opens.

`CAT-04` can be N/A for an initial listing. For an update, review the SHA-bump PR/range. Never claim maintainer admission is a prerequisite for submitting the hackathon form. The event year is not assumed from the announcement body. HACK-05 requires a supplied event year and evidence supporting the fixed-EST deadline assessment.

An old pre-deadline review cannot keep `ready_to_submit` true after the event's current cutoff. Historical submitted/admitted evidence is separate from permission to make a new late submission. For this captured event, official X oEmbed dates the exact announcement November 4, 2026, supporting the November 11, 2026 at 5PM EST cutoff.

The report retains raw static checks and a separate `assessment`. Top-level `reviewed_*` labels identify the highest complete reviewer gate, while `certified` remains false. No automatic model call, publication or activation follows a ready result. The caller chooses a CLI `--gate`; only that gate's complete reviewer assessment returns exit 0.

## Migration from 0.1

The old `reviews` field is a legacy worksheet and remains ignored, even if filled with pass values. Use `decisions` and evidence bindings instead. Bare `--submission` fields remain author attestations, not evidence-backed approvals.

## Two-source review from 0.3

The report now exposes Build-guide conformance and Competition and catalog readiness as separate tracks. Every `DEV-*` decision belongs to code readiness and therefore to every later readiness gate. A competition-only review cannot complete code readiness. Track status is `blocked`, `needs_review`, or `reviewed`; the last means accountable evidence-backed review, never official approval. Invalid/stale assessments cannot contribute completed track decisions. Unresolved related source findings and global coverage/source-integrity failures prevent a reviewed track.

The policy now includes actual guide quotes with capture line references plus complete pinned official Markdown. This changes the policy digest. Pre-0.3 records must be regenerated and reviewed, not automatically migrated or re-signed with their old decisions. Schema 1 remains usable because these are additional requirement IDs and stricter policy bindings, not a change to evidence semantics.
