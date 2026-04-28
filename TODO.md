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

- None known.
