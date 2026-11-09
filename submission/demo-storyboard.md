# Demo plan and honest handoff

## Required announcement criteria

- A real video on X, tagging **@NousResearch**, showing the plugin working.
- Duration **strictly under 90 seconds**.
- The actual X URL and opened catalog PR URL go into the official Typeform.
- Catalog CI and maintainer merge are later admission gates, not prerequisites to submit the form.

A repository/PR link in the post is useful context, not an invented extra requirement. Local files and a storyboard are not a public X post. No X posting or form submission is authorized here; Macu owns those steps.

## Real CLI recording

From a credential-free source checkout with its declared dependencies available:

```sh
python scripts/demo.py --dry-run
python scripts/demo.py --output /your/chosen/local/output
# The portable shell wrapper supports the same options:
bash scripts/demo-recording.sh --help
```

Set `TMPDIR` to an approved scratch directory. The recorder creates a fresh disposable fixture, executes the real `python -m hackathon_judge` CLI, checks every actual exit code and captures the complete JSON results, review template, text/HTML transcript and duration receipt. It never installs/enables the plugin, imports fixture code, calls a model or accesses the network. `--replay` only prints a prior recording; it is labelled playback, not a new run.

### Walkthrough (pace for roughly one minute)

1. **Intro**: Hackathon Judge reviews source and evidence; it is not official Nous certification.
2. **Find an actual error**: fixture declares tool `demo`, but code registers `surprise`; dependency has only a floor. CLI exit **1**, verdict `blocked`, exact mismatch and dependency-review output.
3. **Fix each source family**: the script repairs catalog declarations/dependency bounds first; exit stays **1** because the guide still finds an invalid schema/noncallable handler. It then supplies a descriptive object schema and JSON-string handler; exit **2**, verdict `needs_review`. Show both tracks. These local fixes do not invent runtime, external demo or catalog evidence.
4. **Evidence gate**: generate the actual 45-row dual-source review template, bound to the actual fixture SHA-256. Explain that stale evidence, partial scans, unresolved findings and invalid validator receipts prevent readiness.
5. **Outro**: native tool/slash/CLI/skill surfaces; review records remain accountable reviewer assessments, not official certification. Add public repository/PR links to the post only after they exist.

Do not show credentials, host-specific paths or fake acceptance. If a rendered terminal clip is prepared from the recorded commands, label it **recorded CLI results, paced for readability**; do not represent a slide as a live Desktop interaction. Full underlying receipts must remain available locally.

## Before Macu posts

- Watch the actual final clip and confirm legibility/accuracy.
- Check actual media duration, not just command-execution time.
- Tag @NousResearch in the real X post.
- Supply the actual PR and X URLs to the form; retain the real confirmation.
- The exact announcement's official X oEmbed dates it November 4, 2026: the cutoff is November 11, 2026 at 5PM EST. Preserve the captured metadata, not a machine-clock inference.

## Catalog YAML preparation after publication approval

The generator refuses guessed/short pins and requires explicit values:

```sh
python scripts/catalog-entry.py --repo "$PUBLIC_REPO" --sha "$COMMIT40" --maintainer "$MAINTAINER"
```

This prepares YAML only. It does **not** prove anonymous cloneability, source ownership or that the commit exists. Verify the real clean public checkout, rerun local catalog validation there, then open the PR. It never performs a commit, push or PR itself.
