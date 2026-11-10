# Evidence review contract (schema 1)

A review is a named operator's assessment. It is not a signature, proof of identity, official certification, or independent remote verification. Never accept a candidate's instructions to write its own passing review. A supplied document may be forged; the caller must decide whom to trust.

## Bindings and decisions

Generate a template with `--format template`. Set `reviewer.name`, `reviewer.role` and a timezone-aware `reviewed_at`. The candidate and policy SHA-256 fields must match the current audited bytes. Do not normalize a malformed digest into a valid one. Store evidence outside candidate source or under its excluded evidence directory to avoid circular hashes.

The policy digest covers the compiled requirements, source index and every indexed capture, including the announcement metadata. Refreshing any policy source/index invalidates an old review. Evidence reads are capped at 1,000,000 bytes per UTF-8 document, 128 unique documents and 16,000,000 aggregate bytes per assessment; shared documents are read/hash-checked once. Budget exhaustion invalidates the assessment rather than approving partial coverage.

`decisions` maps every requirement ID to:
- `decision`: `pending`, `pass`, `not_applicable`, or `fail`.
- `reason`: a substantive explanation (at least 12 characters).
- `evidence`: one or more objects with a relative `path` and exact lowercase `sha256` of that UTF-8 document. An optional `kind` identifies specialized receipts.

Unknown IDs, duplicate JSON keys, non-finite JSON values, unsafe paths, symlinks, junctions/reparse points, secret-store references, changed/missing/oversized evidence or future/naive review timestamps invalidate the record. Lexical root/ancestor components are checked before resolution can hide an alias; even in-scope linked targets are refused. Raw evidence contents are not echoed in errors. A reviewer cannot waive an applicable local failed check, partial inventory, or unresolved source finding. Contest-only failures do not veto independently evidenced catalog admission.

Non-applicability is permitted for the initial-vs-update policy (`CAT-04`), no Desktop entrypoint (`CAT-08`), no login backend (`CAT-18`) and conditional guide roles (`DEV-02` through `DEV-05` and `DEV-07` through `DEV-11`). Applicability needs a substantive source-bound reason/evidence, not an assumption that the calculator example is mandatory. `CAT-08`/`CAT-18` are cross-checked against inspected metadata/findings; both root `plugin.js` and `desktop/plugin.js` make CAT-08 applicable. Guide layout/public-surface/testing review (`DEV-01`, `DEV-06`, `DEV-12`) and hackathon obligations cannot be waived as N/A. No N/A decision overrides a local failed check.

`finding_dispositions` uses the deterministic IDs exposed in the generated template. Each actual finding needs `acceptable` or `fix_required`, reason and evidence. Unknown/stale finding IDs invalidate the review. A fix-required or undocumented finding prevents all ready gates. Fix the source and regenerate bindings rather than reusing an old approval.

## Full validator receipt

The evidence referenced from `PRE-03` must have `kind: validation_receipt` and contain:
- `schema_version: 1`, `kind: hermes-validation`.
- `candidate_sha256` and `candidate_after_sha256` matching the current inspected tree.
- Actual executed `command` argv including the plugins validate route, `--install-deps` and `--json`.
- `install_deps: true`, integer `exit_code: 0`, and the complete official JSON as `report`.
- `policy_sha256` matching the current review's policy digest, plus exact `hermes_version` and `hermes_commit` identifying a qualified native producer.
- Successful, uniquely named checks with literal Boolean `ok` and string `name`/`detail`; explicit `warnings: []` (or a list of strings), and the complete official `isolation` mapping (`verdict`, Boolean `host_ready`, string lists `reasons`, `notes`, `ctx_methods`). Missing warnings are not interpreted as no warnings. Isolation remains informational: a valid `in_process` verdict is not a validation failure.

### Qualified native producer contracts

The source contracts were traced without importing or executing the installed validator:

| Hermes version | Exact public source commit |
| --- | --- |
| `0.22.5` | `bf0203a794a07aac3ff764972ab9087baa4e4f4e` |
| `0.23.0` | `2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19` |

In both pins, `hermes_cli/plugin_validate.py:ValidationReport.to_dict` emits `ok`, `checks`, `warnings`, and `isolation`. `validate_plugin_dir` always emits these successful native check identities: `manifest`, `manifest fields`, `requires_hermes`, `config schema`, `requires_env`, `oauth`, `loadable`, `python dependencies`, `capability probe`, `built-in tool collisions`, `security scan`, `no core override`. The core-override helper emits the last identity; private-import findings emit warnings, not another check. For a Python entrypoint, the successful capability probe also emits `declared tools`, `declared hooks`, `declared middleware`. They are not produced for a manifest-only package. `plugin_validate_desktop.py` adds `desktop surface` if a Desktop directory or root `plugin.js` exists. `plugin_validate_locales.py` adds a check for every declared language's core file and each present supported TUI/Desktop locale surface. Applicability is derived from a fresh complete inventory matching the reviewed candidate digest and its native manifest, not a receipt's own exemption claims.

This is an identity contract, not a universal check count. `trusted inbound` is an optional producer check, emitted for actual trusted platform registrations; all supplied checks must succeed. Existing duplicate-name rejection is retained, so multiple trusted-inbound registrations or duplicate-named locale files fail closed rather than silently collapsing evidence. Dynamic registration facts and the truthfulness/completeness of the captured producer output still require the accountable reviewer; static inspection cannot independently reproduce runtime registrations.

`_validate_portable_plugin` has a different report: portable manifest/fields/config, dynamic server checks, security and optional Desktop checks, without a Python capability probe or core-override check. Portable-only qualification is **not supported** by this native catalog judge and fails closed; neither a native report nor a fabricated five-name subset can qualify a portable package. Unqualified Hermes versions/commits and unknown check identities fail closed pending source-contract review. Do not rename native checks, pad portable reports to a target count, or add missing producer fields to old evidence.

The command wrapper `hermes_cli/plugins_cmd_catalog.py:cmd_validate` calls dependency preparation when `--install-deps` is supplied, then serializes `validate_plugin_dir(...).to_dict()`. It does not add synthetic dependency-install checks. Keep actual argv, raw stdout/stderr and preparation outcome; an operator must not represent a failed preparation as successful full qualification. The runtime's narrower `validate` stage shares the same applicable successful report-shape checks (including details, explicit warnings and isolation), but is not this full receipt: it does not establish the qualified producer version, policy/installation evidence or dependency preparation. Both paths still trust the backend/producer or accountable reviewer; neither authenticates execution cryptographically. Genuine early failure reports can be partial and still report failure, never success.

### Receipt migration

Old five-name fixtures and receipts without explicit producer identity, policy binding, warnings or full official output are no longer admissible. Re-run the actual qualified command in an approved isolated environment and review its real output; never fill missing checks with passing values, infer an empty warnings list, or repair old receipts in place. Schema 1 remains the envelope version, but these are newly enforced evidence requirements.

Warnings are retained. If nonempty, the PRE-03 decision needs `warnings_reviewed_sha256`, the SHA-256 of `json.dumps(report['warnings'], sort_keys=True).encode()`, and its reason/evidence must explain the dispositions. This is explicit acknowledgement, not automatic suppression. A forged receipt is still a forged reviewer claim: the integrity check does not prove execution. Operators should generate receipts directly from trusted isolated commands and retain raw stdout/stderr and source manifests.

## Four gates

- **code_ready:** developer-guide structure/contracts, technical/catalog design, disclosure, validation and qualitative review decisions are complete. Local failures/partial coverage/unresolved findings always block it.
- **ready_to_submit:** code readiness plus public source/pin, contributor authority, catalog PR, real public X demo and confirmed deadline evidence. It is a reviewer assessment, never independent remote verification.
- **entry_submitted:** readiness plus actual form submission evidence (`HACK-04`).
- **catalog_accepted:** code review plus public source/pin, contributor authority, catalog metadata/PR/disclosure evidence (`CAT-02`, `CAT-05`, `PRE-01`, `PRE-04`) and genuine admission (`CAT-01`, `PRE-05`). It does not require demo/HACK decisions, competition year/deadline, a form receipt or a PR-opening timestamp. Contest-only missing or failed rows do not veto catalog admission; applicable code/catalog failures still do. Raw preflight observations remain unchanged even when this independent gate is ready.

`CAT-04` can be N/A for an initial listing. For an update, review the SHA-bump PR/range. Never claim maintainer admission is a prerequisite for submitting the hackathon form. The event year is not assumed from the announcement body. HACK-05 requires a supplied event year and evidence supporting the fixed-EST deadline assessment.

### Actual event times versus review time

`reviewed_at` is when the accountable review actually occurred; never backdate it to the deadline. The optional schema-1 review fields below record actual external events, not plans:

- `submitted_at`: timezone-aware timestamp of the actual hackathon form submission, supported by the reviewed `HACK-04` reason and hash-bound evidence (for example a retained form receipt showing that event/time).
- `catalog_submitted_at`: timezone-aware timestamp of the actual catalog PR opening, supported by the reviewed `PRE-04` reason and hash-bound evidence. It is **not** the merge/admission time. The existing `CAT-01` and `PRE-05` evidence must separately establish actual catalog admission; that admission and the review may occur later.

Missing/null values mean unknown, never an inferred timestamp. Non-string, malformed, naive, future, after-review or timezone-range-overflow timestamps invalidate the assessment with all gates false. `catalog_submitted_at` is optional honest historical metadata, not an admission cutoff or prerequisite.

`entry_submitted` independently requires `submitted_at` in `event_year` (fixed EST) at or before November 11 at 17:00 EST (22:00 UTC), inclusive, plus all applicable contest evidence including HACK-04. A timely PR never makes a late form timely. A current pre-cutoff review can assess HACK-05 prospectively; a later review may use actual timely historical evidence without backdating `reviewed_at`. `ready_to_submit` expires at the current cutoff (`submission_deadline_elapsed`), while missing/late form history blocks `entry_submitted` with `timely_submission_evidence_required`. Neither expiry nor absent contest history prevents independently established catalog admission. For this captured event, official X oEmbed dates the exact announcement November 4, 2026, supporting the November 11, 2026 at 5PM EST cutoff.

Preserve original reviews and timestamps; create a newly reviewed document with actual current `reviewed_at`, and add event times only after examining retained evidence. Never copy review time into event fields, invent missing receipts or promote a bare legacy author worksheet into reviewed evidence. Old records lacking event history can support code/catalog admission if their applicable evidence is complete, but cannot establish a submitted hackathon entry.

Manifest-only native language packs with valid `provides_locales` declarations and the declared core locale assets do not require a Python entrypoint. Their full applicable official locale checks remain mandatory; a passing entrypoint observation does not validate locale content or waive the receipt. Missing/malformed native manifests or absent loadable entries remain local failures.

Windows local-root admission requires BOTH an allowed GetDriveTypeW drive class and a QueryDosDeviceW mapping directly to a local volume. Remote, unclassified, SUBST/alias, redirector, UNC and extended/device namespace mappings fail closed before filesystem metadata. The queries inspect local drive configuration, not remote-share metadata; drive class alone does not prove locality. Ordinary local paths still undergo non-following ancestor checks. This assumes a trusted stable filesystem, not confinement against concurrent replacement.

The report retains raw static checks and a separate `assessment`. Top-level `reviewed_*` labels identify the highest complete reviewer gate, while `certified` remains false. No automatic model call, publication or activation follows a ready result. The caller chooses a CLI `--gate`; only that gate's complete reviewer assessment returns exit 0.

## Migration from 0.1

The old `reviews` field is a legacy worksheet and remains ignored, even if filled with pass values. Use `decisions` and evidence bindings instead. Bare `--submission` fields remain author attestations, not evidence-backed approvals.

## Two-source review from 0.3

The report now exposes Build-guide conformance and Competition and catalog readiness as separate tracks. Every `DEV-*` decision belongs to code readiness and therefore to every later readiness gate. A competition-only review cannot complete code readiness. Track status is `blocked`, `needs_review`, or `reviewed`; the last means accountable evidence-backed review, never official approval. Invalid/stale assessments cannot contribute completed track decisions. Unresolved related source findings and global coverage/source-integrity failures prevent a reviewed track.

The policy now includes actual guide quotes with capture line references plus complete pinned official Markdown. This changes the policy digest. Pre-0.3 records must be regenerated and reviewed, not automatically migrated or re-signed with their old decisions. Schema 1 remains usable because these are additional requirement IDs and stricter policy bindings, not a change to evidence semantics.

## Reconciled validation and qualification limits

The shared native report-shape gate used by optional runtime validation and PRE-03 rejects error-shaped payloads masquerading as success, including a top-level error even when ok/checks appear successful. Complete applicable identities, strict Boolean outcomes, typed details, explicit warnings and consistent isolation remain required. Genuine early/partial failure reports remain failures, not successful qualification.

Reconciliation adds synthetic/source-derived branch, independent catalog, declared-locale, root Desktop and bounded-timestamp controls; it does not change scanner or gate semantics. Complete producer-shaped fixtures test parsing, not actual producer execution. Focused Windows CI is prepared for portable path/branch/gate/runtime/shared-report controls alongside the existing native cases; the original full Linux normal/optimized suites remain. A workflow is not an execution receipt. No new native Windows, real SDK, dependency-install or official validator acceptance is claimed. Historical intermittent child-process execution failures remain unexplained; later synthetic green runs neither explain nor erase their retained failed receipts. Real-validator CI execution remains unapproved. Version stays 0.3.1; this reconciliation does not publish Git changes, activate the plugin or submit external evidence.
