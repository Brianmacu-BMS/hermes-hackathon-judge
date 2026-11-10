# Add Hackathon Judge to the plugin catalog

**Catalog entry/update template for version 0.3.1. This template is not publication or submission evidence. The exact qualified source pin, relevant catalog PR, public demo and form evidence are TO BE SUPPLIED in the operation handoff; placeholders are not completed claims. Existing catalog acceptance of an older pin does not qualify a new revision.**

## Functionality

Hackathon Judge reviews local Hermes plugin source against the captured official catalog/hackathon policy and tracks evidence-backed reviewer completion. It combines bounded static checks, source/policy/evidence digests, runtime-validator receipt checks, finding dispositions and separate code/submission/admission gates. It never claims official certification and does not turn an author's checkbox into independently verified evidence.

It covers all 18 canonical catalog rules plus prerequisite, hackathon and qualitative review rows. Applicable local failures, partial coverage, stale evidence and unresolved findings prevent readiness. Catalog admission is independent of competition-only failures and does not require demo/form/deadline evidence or a timely PR-opening timestamp. The default audit does not import candidate code.

## Public Hermes surfaces

- `ctx.register_tool`: `hackathon_judge`, toolset `hackathon_judge`.
- `ctx.register_command`: `/judge-plugin`.
- `ctx.register_cli_command`: `hermes hackathon-judge`.
- `ctx.register_skill`: `hackathon-judge:judge-plugin`.
- `ctx.dispatch_tool`: optional trusted-code validation through the normal terminal approval/budget pipeline.

No core overrides, renderer DOM/prototype patching, private store access, self-updater, login backend or custom Desktop/web UI.

## Rule 13 disclosures

| Behavior | Disclosure |
|---|---|
| Runtime network calls | None during registration, audit, review or reporting. Policy snapshots are packaged, not auto-updated. No remote GitHub/X/form verification is claimed. |
| File reads outside plugin data | Reads the explicit candidate tree, supplied catalog/submission/review documents, and relative hashed evidence below the review document directory, plus packaged rules/sources. UNC/extended/device roots and remote/unclassified Windows drives are refused before filesystem metadata; ordinary local paths and non-following ancestor checks are required. Recognized secret stores are refused/skipped without reading their values. Unknown secret-bearing source filenames cannot be reliably recognized; audit credential-free source only. |
| Shell/child commands | Static runtime makes none. Optional `validate` normally dispatches an approval-visible `python3 -I -B` bootstrap with task/session identity. It verifies the shipped helper and complete backend candidate manifest, then a backend-owned helper launches `hermes plugins validate SNAPSHOT --json` on a verified temporary copy. Exact-candidate authorization and ordinary approval remain required; bare-hermes approval patterns do not automatically cover the new command. A success report must contain every source-applicable native check identity, typed details, explicit warnings and isolation; byte binding still trusts the backend/producer and does not authenticate execution cryptographically. No `--install-deps` is requested. |
| Development scripts | Explicitly invoked demo tooling runs the real CLI on temporary fixtures; release tooling reads source and creates a source-only ZIP/manifest outside the source tree. They are not imported during registration. Qualification commands can prepare dependencies only in disposable runtimes. |
| Writes | Static runtime returns output only. Optional validation creates/cleans a temporary backend snapshot and captured streams; trusted validator/candidate execution has normal backend write/network/environment authority. This is byte binding, not sandboxing or original-location/full-install qualification. Operators may redirect output/save evidence. Development scripts write explicit outputs/fixtures. |
| Background processes | None; no schedules, watchers, persistent helper, update loop or unattended interactive flow. |
| Credentials | None requested/stored/refreshed by static inspection. Recognized credential-shaped names are refused/skipped. Optional trusted execution inherits its backend environment; use a disposable credential-free environment rather than claiming isolation. |
| Telemetry/model usage | None. No analytics, usage reporting, plugin-owned LLM calls, model routing or provider changes. |
| Dependencies | Bounded PyYAML and packaging. Core constraints respected via official isolated validation. CI-only pins and manual release-age policy documented separately; no inherited quarantine guarantee is claimed. |

## Evidence and qualification

Attach the exact source artifact manifest, actual test receipts, Doctor output, full `plugins validate --install-deps --json` result, and reviewed warnings for the public pin. Local development evidence is not a claim that remote catalog CI has run. Re-qualify the clean public checkout after the real SHA exists.

The install scanner may flag credential-related detection strings and quoted policy text. Retain and explain exact current warnings; do not suppress or evade them. The actual warning locations/results are in the qualification handoff, not assumed to remain unchanged after a source edit.

No custom UI screenshots are required for an absent custom UI. A terminal demonstration/screenshot can show the actual tool/CLI results. The hackathon video must separately be posted to X, tag @NousResearch, show real behavior and be strictly under 90 seconds.

## Catalog entry details

- Name: `hackathon-judge`
- Version: `"0.3.1"`
- `requires_hermes`: `">=0.22.5"` in both manifest and entry.
- Tier: `community` (only Nous maintainers assign verified/official).
- Category: `tools`.
- Repository: https://github.com/Brianmacu-BMS/hermes-hackathon-judge.
- SHA: **MISSING — final hardened full 40-hex public commit; do not reuse the earlier 0.2.0 pin or substitute an archive digest**.
- Subdir: omit for a standalone root repository.
- Entry capabilities: tool `hackathon_judge`; no hooks, middleware or required credential environment variables.

## Process distinction

Before opening this PR: public cloneable source, exact full SHA, truthful metadata/disclosures and successful local validation at that source. After opening: a maintainer starts catalog CI and reviews the pin. **Catalog CI/maintainer merge are not prerequisites for opening the PR or submitting the hackathon form.** The form may be submitted as soon as the catalog PR is open and the X demo is posted. No PR, X post or form submission has been performed by this local preparation.

## Reconciled source disclosures (not acceptance evidence)

Windows local-root admission requires BOTH an allowed GetDriveTypeW drive class and a QueryDosDeviceW mapping directly to a local volume. Remote, unclassified, SUBST/alias, redirector, UNC and extended/device namespace mappings fail closed before filesystem metadata. The queries inspect local drive configuration, not remote-share metadata; drive class alone does not prove locality. Ordinary local paths still undergo non-following ancestor checks. This assumes a trusted stable filesystem, not confinement against concurrent replacement.

The shared native report-shape gate used by optional runtime validation and PRE-03 rejects error-shaped payloads masquerading as success, including a top-level error even when ok/checks appear successful. Complete applicable identities, strict Boolean outcomes, typed details, explicit warnings and consistent isolation remain required. Genuine early/partial failure reports remain failures, not successful qualification.

Reconciliation adds synthetic/source-derived branch, independent catalog, declared-locale, root Desktop and bounded-timestamp controls; it does not change scanner or gate semantics. Complete producer-shaped fixtures test parsing, not actual producer execution. Focused Windows CI is prepared for portable path/branch/gate/runtime/shared-report controls alongside the existing native cases; the original full Linux normal/optimized suites remain. A workflow is not an execution receipt. No new native Windows, real SDK, dependency-install or official validator acceptance is claimed. Historical intermittent child-process execution failures remain unexplained; later synthetic green runs neither explain nor erase their retained failed receipts. Real-validator CI execution remains unapproved. Version stays 0.3.1; this reconciliation does not publish Git changes, activate the plugin or submit external evidence.
