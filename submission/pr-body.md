# Add Hackathon Judge to the plugin catalog

**Local draft for the hardened 0.2.1 revision. The source repository exists, but this revision has not been committed or published. The final commit pin, catalog PR, public demo and form evidence are TO BE SUPPLIED; placeholders are not completed claims.**

## Functionality

Hackathon Judge reviews local Hermes plugin source against the captured official catalog/hackathon policy and tracks evidence-backed reviewer completion. It combines bounded static checks, source/policy/evidence digests, runtime-validator receipt checks, finding dispositions and separate code/submission/admission gates. It never claims official certification and does not turn an author's checkbox into independently verified evidence.

It covers all 18 canonical catalog rules plus prerequisite, hackathon and qualitative review rows. Local failures, partial coverage, stale evidence and unresolved findings prevent readiness. The default audit does not import candidate code.

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
| File reads outside plugin data | Reads the explicit candidate tree, supplied catalog/submission/review documents, and relative hashed evidence below the review document directory, plus packaged rules/sources. Recognized secret stores are refused/skipped without reading their values. Unknown secret-bearing source filenames cannot be reliably recognized; audit credential-free source only. |
| Shell/child commands | Static runtime makes none. Optional `validate` uses normal host terminal dispatch, requires exact-candidate authorization and ordinary approval, and executes trusted candidate code via the official validator. It does not automatically request `--install-deps`. |
| Development scripts | Explicitly invoked demo tooling runs the real CLI on temporary fixtures; release tooling reads source and creates a source-only ZIP/manifest outside the source tree. They are not imported during registration. Qualification commands can prepare dependencies only in disposable runtimes. |
| Writes | Runtime returns output only. Operators may redirect stdout/save review evidence. No candidate/config/authentication/memory mutation. Development scripts write only explicit release/demo outputs and temporary fixtures. |
| Background processes | None; no schedules, watchers, persistent helper, update loop or unattended interactive flow. |
| Credentials | None requested, stored, refreshed, rotated or read from credential files. |
| Telemetry/model usage | None. No analytics, usage reporting, plugin-owned LLM calls, model routing or provider changes. |
| Dependencies | Bounded PyYAML and packaging. Core constraints respected via official isolated validation. CI-only pins and manual release-age policy documented separately; no inherited quarantine guarantee is claimed. |

## Evidence and qualification

Attach the exact source artifact manifest, actual test receipts, Doctor output, full `plugins validate --install-deps --json` result, and reviewed warnings for the public pin. Local development evidence is not a claim that remote catalog CI has run. Re-qualify the clean public checkout after the real SHA exists.

The install scanner may flag credential-related detection strings and quoted policy text. Retain and explain exact current warnings; do not suppress or evade them. The actual warning locations/results are in the qualification handoff, not assumed to remain unchanged after a source edit.

No custom UI screenshots are required for an absent custom UI. A terminal demonstration/screenshot can show the actual tool/CLI results. The hackathon video must separately be posted to X, tag @NousResearch, show real behavior and be strictly under 90 seconds.

## Catalog entry details

- Name: `hackathon-judge`
- Version: `"0.2.1"`
- `requires_hermes`: `">=0.22.5"` in both manifest and entry.
- Tier: `community` (only Nous maintainers assign verified/official).
- Category: `tools`.
- Repository: https://github.com/Brianmacu-BMS/hermes-hackathon-judge.
- SHA: **MISSING — final hardened full 40-hex public commit; do not reuse the earlier 0.2.0 pin or substitute an archive digest**.
- Subdir: omit for a standalone root repository.
- Entry capabilities: tool `hackathon_judge`; no hooks, middleware or required credential environment variables.

## Process distinction

Before opening this PR: public cloneable source, exact full SHA, truthful metadata/disclosures and successful local validation at that source. After opening: a maintainer starts catalog CI and reviews the pin. **Catalog CI/maintainer merge are not prerequisites for opening the PR or submitting the hackathon form.** The form may be submitted as soon as the catalog PR is open and the X demo is posted. No PR, X post or form submission has been performed by this local preparation.
