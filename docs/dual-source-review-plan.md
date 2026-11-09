# Dual-source judge review — implementation contract

## Goal
Extend v0.2.2 with explicit developer-guide structure/contract review AND competition/catalog review. Preserve every existing competition/catalog row and gate. New guide rows participate in code readiness; old policy-bound review receipts become stale rather than silently omitting new obligations.

## Sources
Use full UTF-8 official source captures from immutable upstream 8719a66ef8e7e2a1bd705d595767874c66fd8a48. Canonical catalog policy remains unchanged; a stale web extractor incorrectly showed an old six-rule pin-age policy, so direct pinned repository bytes take precedence. Keep announcement and publication-year captures; do not infer event year from the current clock. Runtime remains offline with explicit capture provenance, never a self-updater.

## Changes
- Add 12 DEV requirement rows with guide URLs/anchors, real source quotations and source-capture line references. Preserve 33 existing CAT/PRE/HACK/QUALITY rows.
- Add guide analyzer consuming ONLY the existing bounded, guarded inventory bytes. No imports/execution of candidates, no extra path reads/network/LLM calls. Check entrypoint callable wiring and statically resolvable schema/handler contracts; dynamic/re-exported/specialized cases stay reviewable, not guessed failures or invented passes.
- Report manifest/schema/handler/registration component locations and actionable source-linked diagnostics. Module filenames are not mandated; hooks/skills/data/state are conditional. Simple inline tool schemas/handlers and package re-exports are valid arrangements.
- Add independent JSON/Markdown review tracks for build-guide and competition/catalog requirements. Track statuses remain evidence-aware and non-certifying. Missing DEV decisions block code readiness; required guide rows cannot be waived by unrelated competition evidence. Preserve global fail/partial-inventory/policy-integrity blockers.
- Map guide checks onto existing security/catalog observations where appropriate. Preserve human-review gates for public APIs, capabilities, secret/profile/state/path ownership, declared dependencies, lifecycle/bundled assets and real testing. Recommendations are not universal admission bans.
- Bump isolated candidate to 0.3.0; update docs, bundled operating skill, demo and tests consistently. No commit/push/publication, installation/activation, dependency mutation, model routing or live configuration changes.

## Validation
Write focused synthetic regressions and run RED on the unchanged engine before implementation. Exercise both tracks, missing register, alternate module layout, valid re-exports, dynamic wiring, malformed schemas, non-JSON literal handler returns, optional surfaces, guide-decision readiness blocking and source quotation/capture integrity. Run the complete inherited suite normally and under -O. Build a source-only ZIP, verify membership/hashes/modes, restore to fresh approved scratch and repeat the full suite, static payload scan and actual CLI demonstration. Run a static-only report on the previously qualified Backup Sentinel source export; do not execute/install it or inspect real backups. Save receipts and source-bound review findings outside candidate source.

## Remaining gates
Official loader/doctor/installed dispatch, remote CI, native Windows requalification, publication and marketplace pin changes are unrun unless separately authorized. A valid old snapshot is not a live freshness check. The output is accountable preflight/reviewer assessment, never official acceptance or proof of winning.
