# Submission-candidate implementation plan

## Goal and non-negotiable hold
Upgrade v0.1.0 into a tested, evidence-backed judge and prepare its submission materials. Never install or enable it in the live/default profile, and do not enable an isolated profile on this host either. Doctor/validator's ephemeral registration is test execution, not deployment. No public repository, commit/push, PR, X post or form submission without explicit user authorization and approved target/content.

## Isolated revision
`/home/hermes/projects/hermes-hackathon-judge-v0.2.0` contains hash-verified v0.1.0 source only, without old bytecode, operation closeouts or machine-specific verification scripts. Original source/release/receipts remain unchanged.

## Workstreams
1. Capture current official canonical catalog rules/developer guide/announcement; preserve 18+5+5+5 coverage and separate code, entry, and post-submission admission gates.
2. Add review completion backed by a candidate-tree digest, source-policy digest, per-rule evidence file hashes, reviewer identity/reason/timestamps, explicit non-applicability and finding dispositions. Supplied evidence is checked for file integrity, not magically trusted as an external fact. Missing/modified evidence and local failures prevent readiness; maintainer merge is not a pre-submit requirement.
3. Harden scanner/metadata handling, bounded filesystem/report output and malformed inputs; preserve all relevant warnings, reduce false positives contextually without self-exemptions.
4. Provide portable source-only packaging, real deterministic demo, operator docs, catalog/PR/form drafts, dependency policy and checksummed qualification receipts. No placeholders may be presented as completed entry gates.
5. Exercise TDD regressions, all existing tests, real Doctor and full catalog validation in fresh temporary data roots with no plugin enablement, extracted-package behavior and self-audit. Pin exactly which source bytes ran.
6. Independently review, document all remaining external/owner-dependent gates, and keep activation held even after local tests pass.

## Readiness definitions
- `code_ready`: source artifact qualified and all applicable technical/manual review evidence complete.
- `ready_to_submit`: required public source/pin, opened catalog PR, real X working demo under 90 seconds/tag and form fields are verified by an accountable reviewer; form itself need not already be submitted.
- `entry_submitted`: real form confirmation and timestamp supplied/reviewed.
- `catalog_accepted`: downstream maintainer/CI/merge evidence, never claimed from local tests.

No hidden LLM calls, routing changes, network credential routes or auto-approval mechanisms are introduced. A reviewer record is an accountable assessment, not official Nous certification.
