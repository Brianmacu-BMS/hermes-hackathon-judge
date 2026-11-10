# Hermes Hackathon Judge

**Version 0.3.1 — correctness repairs for two-source plugin conformance and submission review.**

Hackathon Judge helps plugin authors find submission problems before reviewers do. It inspects source without importing candidate code, runs through the complete captured policy checklist, and can complete an **accountable reviewer assessment** when every required decision has source-bound evidence. It is not an official Nous judge, a security sandbox, or a substitute for watching the demo.

## What makes it a plugin rather than another checklist?

- Executable Python/JavaScript heuristics with file/line findings, not just instructions.
- Manifest, registration, dependency, catalog metadata and payload checks.
- Integrity checks for policy snapshots, candidate trees and review evidence.
- A native Hermes tool, slash command, CLI command and namespaced skill using public APIs only.
- Four distinct readiness gates: code, submission preparation, submitted entry, catalog admission. An unmerged PR does not block submitting the hackathon form.
- Review completion that fails closed on changed evidence, unresolved findings, invalid receipts or local failures. No green checkbox can waive a failed check.

The captured checklist contains **45 requirement rows**: 12 developer-guide obligations, 18 catalog rules, five prerequisites, five hackathon requirements and five qualitative criteria. No numerical judging weights or winning score are invented.

## Two sources, two visible review tracks

Every audit checks both:

1. **Build-guide conformance** — the official [Build a Hermes Plugin](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins) structure and contracts. `DEV-01` through `DEV-12` cover layout, callable registration, descriptive schemas, JSON-string handler results/errors, declarations, public APIs, profile-owned settings/state, bundled assets/skills, dependencies/secrets, optional hooks, session paths and real testing evidence.
2. **Competition and catalog readiness** — the announcement's entry/demo/form/deadline/qualitative criteria plus the canonical catalog admission/submission requirements. These remain separate from the question of whether the plugin is implemented correctly.

JSON exposes `tracks` and `guide_analysis`; Markdown separates the two checklists and shows component files plus file/line diagnostics and next actions. Guide rules include the source URL/anchor, actual quotation and capture line references. Capture hashes and quote bindings are checked locally. A clean source shape is not an evidence-backed completed review.

**Check the roles, not the calculator's filenames.** Manifest, registration, schemas and handlers must be wired appropriately, but they can use inline definitions, package re-exports or different module names. Hooks, skills, data files and persistent state are optional. Specialized/Desktop/dashboard/portable surfaces need their applicable documented contracts; the generic Python analyzer does not pretend to prove every SDK. Dynamic factories, decorated handlers and shadowed bindings remain review items instead of guessed passes or false failures.

Guide decisions are part of `code_ready`; approving only competition rows cannot skip them. Existing pre-0.3 reviews bind the old policy bytes and must be regenerated. `not_applicable` is evidence-backed and allowed for conditional guide roles, never to waive a detected failure. `certified` remains false.

Runtime audits remain offline: they read complete **pinned captures**, not live websites and not a self-updating rule engine. This release's build/submission captures come from immutable upstream `8719a66ef8e7e2a1bd705d595767874c66fd8a48`; the source manifest records provenance. Recheck official sources before submitting.

## Run without installing or activating

Requires Python 3.11+ with PyYAML and packaging. Inside Hermes use its existing environment; declared plugin dependencies are prepared by Hermes PM during an operator-approved installation. Do not pip-install into a managed Hermes environment.

From this source directory:

```sh
python -m hackathon_judge /path/to/candidate
python -m hackathon_judge /path/to/candidate --catalog /path/to/entry.yaml --format json
python -m hackathon_judge /path/to/candidate --format template > /separate/evidence/review.json
python -m hackathon_judge /path/to/candidate --review /separate/evidence/review.json --gate code_ready
python -m hackathon_judge /path/to/candidate --review /separate/evidence/review.json --gate ready_to_submit
python -m hackathon_judge --rules
```

Output formats: Markdown, JSON or review template. Exit **0** means the explicitly selected reviewer gate is ready (or help/rules were listed), **1** means a blocker/rejection, **2** means evidence/review remains incomplete, and **3** means an invalid request or audit error. The standalone module returns bounded JSON for invalid arguments. Native `hermes hackathon-judge` argument parsing is host-owned: invalid options/choices can still exit **2** on stderr before the plugin handler runs. An ordinary source-only audit never certifies the candidate or invents evidence.

### Hermes interfaces, after separately approved activation

- Tool `hackathon_judge`: `audit`, `rules`, `template`, `validate`; optional `catalog`, `submission`, `review` paths.
- `/judge-plugin /path/to/candidate --review /path/to/review.json`.
- `hermes hackathon-judge /path/to/candidate` with the same CLI flags.
- Skill `hackathon-judge:judge-plugin`.

Native tool and slash-command candidate, `--catalog`, `--submission` and `--review` paths use the calling session's working directory through public `agent.runtime_cwd` helpers. An explicitly scoped missing/nonabsolute workspace is refused rather than replaced with another directory; absolute requests remain usable. Relative native inputs fail cleanly if the required helpers are unavailable. Slash paths preserve literal Windows backslashes; single/double quotes group spaces. The standalone `python -m hackathon_judge` and terminal `hermes hackathon-judge` CLI retain ordinary process-working-directory semantics. Evidence paths inside a review record remain relative to that record's directory. No command changes the gateway's process cwd or resolves away lexical links before the existing guards inspect them.

There is no custom Desktop renderer/DOM integration. Native conversation/command surfaces work without a Desktop SDK workaround. Development qualification does **not** imply installation or activation; this candidate is held inactive in its development environment.

## Evidence-backed review

See [the review contract](docs/review-contract.md). Generate the template, inspect the actual source and external evidence, and fill `decisions` with a named reviewer, timezone-aware timestamp, reason and SHA-256-bound local evidence documents. Every source finding also needs an explicit disposition. Evidence paths are relative to the review document's directory; escaping paths, symlinks, junctions/reparse points and recognized credential stores are refused.

`PRE-03` additionally requires a structured real validator receipt binding the before/after candidate digests, `--install-deps` invocation, exit code and complete applicable native official JSON, including explicit warnings and producer version/commit qualification. Five common check names are not a complete report. Validator cautions require an explicit acknowledgement of the exact warnings digest. A changed tree or policy makes the review stale. Review records do not alter the original static observations. Honest later reviews can assess actual on-time submissions using independently evidenced `submitted_at`; optional `catalog_submitted_at` is PR-opening history, not an admission cutoff; `ready_to_submit` still expires. See the contract for migration and independent gate requirements.

**Trust boundary:** hashes identify evidence bytes. They do not prove a reviewer's identity or honesty, authenticate a remote GitHub/X/form event, or make this official Nous approval. The results are labelled `reviewed_*` and `certified` stays false. Applicable local failures and partial inventory block readiness; contest-only failures do not veto independent catalog admission. Catalog admission requires code/public-source/catalog/disclosure/admission evidence, not demo/HACK rows or competition timestamps. Reviewer data and candidate files are untrusted data, not instructions to execute.

Legacy v0.1 `reviews` worksheet notes remain ignored; v0.2 uses `decisions` and `finding_dispositions` with actual evidence. A bare author declaration or link is never promoted into independently verified evidence.

## Trusted-code validation

Static audits execute **no candidate code**. The optional tool action `validate` requires literal `trusted_code: true` and uses the host's normal terminal approval/budget pipeline, forwarding task/session identity. The approval-visible command is now a `python3 -I -B` bootstrap, not a bare `hermes plugins validate` command; existing approval patterns for the latter do not automatically cover it. The flag is not user authorization, a sandbox or an approval bypass.

The selected backend must have `python3`, `hermes` and this exact release's `hackathon_judge/bound_validation.py` at the dispatched path. The bootstrap verifies helper bytes; the helper requires the complete backend candidate to match the audited file/size/hash manifest, copies verified bytes into a temporary backend snapshot, runs `hermes plugins validate SNAPSHOT --json` as its child process, and checks both trees afterwards. Missing/old helpers, different backend bytes, ignored/incomplete trees or an oversized command fail closed. Use a clean exported candidate, not a checkout containing ignored `.git`/dependency/evidence directories. Matching path strings alone never establish identity. Temporary files are cleaned on normal completion.

This changes the candidate location and provides byte binding under a trusted, stable backend filesystem—not a sandbox, proof of original-location behavior or protection from a hostile same-user writer. Validator/candidate code inherits the backend environment and can access resources outside the snapshot. A runtime pass requires the complete source-applicable native producer check identities, typed details, explicit warnings and isolation, using the same report-shape gate as PRE-03. No dependency installation is requested; this runtime result does **not** satisfy the separate full `PRE-03` receipt. Use a disposable credential-free runtime for safety-sensitive qualification.

Full admission checks belong in a disposable environment, on the exact source commit to be pinned:

```sh
hermes plugins doctor /path/to/trusted-candidate --ci
hermes plugins validate /path/to/trusted-candidate --install-deps --json
```

Both execute trusted plugin code. Doctor's temporary profile is not a sandbox. `--install-deps` can change the selected interpreter environment; do not point release preparation at a live environment. Review all warnings and exercise success/failure/unattended behavior separately. No operation in this project automatically enables a candidate.

## Disclosures

| Behavior | Scope |
|---|---|
| Network | No static audit/review/report/registration network calls or remote PR/X/form fetches. Approved validator/candidate execution has normal backend authority and can use its network. Captures do not self-update. |
| File reads | Explicit candidate directory, supplied catalog/submission/review documents, referenced evidence beneath the review directory, and this plugin's packaged policy captures. |
| Writes | Static runtime returns results without candidate/config/authentication/memory writes. Optional validation creates/cleans a temporary backend snapshot and captured streams; trusted validator/candidate code is not write-confined. stdout redirection is the operator's action. |
| Commands | Optional trusted validation dispatches the hash-checked Python transaction through the normal terminal; its helper launches the official validator child without `--install-deps`. Development/demo/release commands run only when explicitly invoked. |
| Background activity | None: no scheduled jobs, persistent processes, update loop or watchers. |
| Credentials | Static audits do not request/store/refresh credentials; recognized names/stores are refused or skipped without content reads/hashes, using case-insensitive comparisons. Secret-bearing ordinary source names cannot be reliably detected. Optional trusted execution inherits its backend environment/authority; do not use secret-bearing candidates or treat this as credential isolation. |
| Telemetry and model usage | None. No analytics, hidden LLM calls, provider selection or model routing changes. Human/agent qualitative review happens outside the plugin's deterministic runtime. |
| Dependencies | Bounded PyYAML and packaging requirements. CI-only versions are pinned separately. No dependency-age guarantee is inherited from Hermes; see [dependency policy](docs/dependency-policy.md). |

## Coverage and limitations

Default limits: 10,000 file entries, 10,000 directory entries, 2 MB per candidate file and 32 MB total; evidence documents are separately bounded to 1 MB each, 128 unique documents and 16 MB aggregate per assessment, with shared documents cached. Symlinks, junctions/reparse points, special files, unreadable paths and budget exhaustion prevent readiness. Read operations are bounded but are not a hardened sandbox against malicious concurrent ancestor-directory replacement.

Windows local-root admission requires BOTH an allowed GetDriveTypeW drive class and a QueryDosDeviceW mapping directly to a local volume. Remote, unclassified, SUBST/alias, redirector, UNC and extended/device namespace mappings fail closed before filesystem metadata. The queries inspect local drive configuration, not remote-share metadata; drive class alone does not prove locality. Ordinary local paths still undergo non-following ancestor checks. This assumes a trusted stable filesystem, not confinement against concurrent replacement. Ordinary local absolute/relative paths remain supported. Scoped cwd ancestors are checked non-followingly before directory predicates. Path checks inspect lexical components **before** resolution, including the selected root and its ancestors. Linked/reparse roots are invalid requests; linked/reparse descendants are pruned and make inventory incomplete. Explicit document reads refuse them even when their targets stay in scope. The legacy JSON `symlinks` list includes refused junctions/reparse paths too. This deliberately rejects all reparse tags, including managed cloud directories: use an ordinary local copy instead. The source archive builder uses the same stable-path guard.

Manifest-only declared language packs with core locale assets need no Python entrypoint, but still require full applicable official locale-check evidence. Both root `plugin.js` and `desktop/plugin.js` require CAT-08 review.

`.git`, virtual environments, dependency caches and `evidence/` are excluded and listed. Runtime heuristic scanning excludes tests/fixtures/source-documentation directories; inventory and payload checks still inspect them outside ignored directories. Bundled runtime code in excluded directories needs explicit review. Archives are flagged, not unpacked. Header-based binary detection is heuristic and does not verify native build attestations.

The tree digest describes **inspected files**, not a Git SHA, public repository or clean commit. Public access, exact pin correspondence, ownership/lineage, demo content/tag, real form confirmation and maintainer acceptance remain accountable external-review obligations. Compatibility results must name the actual Hermes/Python/platform tested; do not infer every platform or minimum release from one passing local run.

## Sources

- [Hackathon announcement](https://x.com/NousResearch/status/2118094256438936062)
- [Catalog submission guide](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins/catalog-submission)
- [Canonical catalog policy](https://github.com/NousResearch/hermes-agent/blob/main/plugin-catalog/README.md)
- [Plugin developer guide](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins)
- [Official entry form](https://form.typeform.com/to/FwJLvOln)

Complete captures, UTC retrieval timestamps and hashes are indexed by `sources/manifest.json`. Check the canonical source before final submission; a verified old snapshot is not a live freshness check. No self-updater exists.

The deadline is **November 11, 2026, 5PM EST (UTC-05:00)**. The announcement body omits its year, but X's official oEmbed dates this exact post November 4, 2026; that metadata is captured separately in `sources/announcement-oembed.json` and indexed with its hash. Do not infer an event year from the machine clock. The demo must be **strictly under 90 seconds**, show the plugin working, be posted on X and tag **@NousResearch**. The public catalog PR and X demo links go into the official form. CI/maintainer admission is distinct from eligibility to submit an opened PR.

## Development, release and handoff

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
```

Use a disposable non-Hermes test environment for `requirements-test.txt`. CI defines the full Linux Python 3.11–3.14 suite and focused native Windows path/URL/checkout regressions; a workflow definition is not a passing result. Windows junction tests skip on Linux, and Linux attribute models do not establish native Windows acceptance. The catalog-entry generator remains Linux-only until broader runtime qualification is available.

`.gitattributes` enforces LF for text and executable scripts while preserving the exact bytes of packaged source captures and compiled policy. Never regenerate capture hashes merely to conceal checkout conversion. Checkout/archive regressions exercise `core.autocrlf=true` in disposable repositories without changing global Git settings.

Source-only release tooling and a real CLI demo workflow live under `scripts/`; submission/PR/demo handoffs live under `submission/`. Repaired source needs a new immutable public commit and new qualification receipts; passing CI or reviews for an earlier commit do not qualify an edited tree. Final SHA/PR/X/form evidence is deliberately not filled with invented values. Keep release receipts outside distributed source and never ship caches or credentials.

### Reconciled report and proof boundaries

The shared native report-shape gate used by optional runtime validation and PRE-03 rejects error-shaped payloads masquerading as success, including a top-level error even when ok/checks appear successful. Complete applicable identities, strict Boolean outcomes, typed details, explicit warnings and consistent isolation remain required. Genuine early/partial failure reports remain failures, not successful qualification.

Reconciliation adds synthetic/source-derived branch, independent catalog, declared-locale, root Desktop and bounded-timestamp controls; it does not change scanner or gate semantics. Complete producer-shaped fixtures test parsing, not actual producer execution. Focused Windows CI is prepared for portable path/branch/gate/runtime/shared-report controls alongside the existing native cases; the original full Linux normal/optimized suites remain. A workflow is not an execution receipt. No new native Windows, real SDK, dependency-install or official validator acceptance is claimed. Historical intermittent child-process execution failures remain unexplained; later synthetic green runs neither explain nor erase their retained failed receipts. Real-validator CI execution remains unapproved. Version stays 0.3.1; this reconciliation does not publish Git changes, activate the plugin or submit external evidence.
