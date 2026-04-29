# TODO

## Critical

All critical issues resolved. ✅

## High

All high priority issues resolved. ✅

## Medium

- [x] **Host OS / Node reporting** — **DONE**
  - Added structured `Host` output with `ContainerImageOs`, `VisibleKernel`, `RuntimeReportedHostOs`, `Hardware`, and `Fingerprint`.
  - Added distro, architecture, kernel flavor, runtime host source, and fingerprint stability normalization.
  - Added safe host enrichment from Docker `/info`, Podman `/libpod/info`, Kubernetes `status.nodeInfo`, and cloud metadata.
  - Added privacy-aware `CRP-HOST-FP-v1` host fingerprinting with deterministic hashing and excluded sensitive signals.

## Verified Done

- [x] Build succeeds with 0 warnings/errors (`dotnet build -c Release`)
- [x] Test suite covers host parsing, normalization, fingerprinting, renderers, and fake runtime metadata mapping
- [x] CLI tool produces host reporting for `--format json/markdown/text`
- [x] Docs updated for host reporting, fingerprint privacy, and examples

## Final Open Points

- [ ] **`SampleRegressionTests` pre-existing failure** — `docs/samples/examples/*.sample.json` files
  are missing from the repository. This failure predates the `feat/static-detection-map` branch.
  Adding those files would fix the test.
- [ ] **Git history cleanup** — The early commits `Vendor curated os-release fixtures` and
  `Use license-safe detection map fixtures` on `feat/static-detection-map` contain GPL data in
  history. Consider `git rebase -i` squash/drop before merging to `main` if history cleanliness
  matters.
- [ ] **Override-Loader (stretch)** — `DetectionMaps.LoadOverrides(string? path)` + `--detection-map`
  CLI flag for user-supplied custom maps at runtime.
