# Dependency and release policy

Runtime uses Python's standard library plus bounded `PyYAML>=6.0,<7` and `packaging>=24,<27`. PyYAML supplies SafeLoader/compose, and packaging supplies the public Requirement/specifier API. No model/provider SDK, network client, binary payload, vendored executable or auto-downloader is added. Hermes's core exact constraints remain authoritative during `plugins validate --install-deps`.

CI-only versions are exact pins in `requirements-test.txt`, independent of runtime bounds. CI installs only in a disposable test runner, not a managed live Hermes environment. The workflow uses full commit-pinned Actions, read-only permissions, no stored checkout credentials, no `pull_request_target`, and no plugin activation.

A plugin does not inherit Hermes's dependency release-age guarantee. When changing these pins/bounds, review the oldest supported API floor, upstream changes/security reports, install compatibility and Python wheels. Prefer releases at least three days old, verify the actual release timestamp, and document any justified exception before publication. There is no hidden runtime quarantine check or automatic dependency update; do not advertise one. Re-pin dependencies only through a source change and reviewed release, and rerun isolated validation under Hermes's constraints.

Build the source archive from the explicit release include rules. Test scripts and documentation are reviewable source. Generated caches, local evidence, virtual environments and Git internals are not distribution inputs. Native binaries, committed bytecode or archives must not enter the source payload; do not rely on filename extensions to identify machine code. A future genuine native dependency would require the canonical catalog's source/build-attestation policy and a new review, not a checksum-only exception.

No self-updater exists. Users receive catalog changes only through a reviewed full-SHA pin update and Hermes's own plugin update path.
