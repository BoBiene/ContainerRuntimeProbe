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

## Review Follow-Up (2026-04-29)

### Critical

- [ ] **1. Parallel probe execution** — `ContainerRuntimeProbeEngine.RunAsync` still awaits probes serially.
- [ ] **2. Shared IMDS client/pooling** — AWS/Azure/OCI defaults still fan out to separate clients for `169.254.169.254`.
- [x] **3. Kubernetes TLS mode** — default remains compatibility-first so in-cluster probing just works, but the report now emits `KUBERNETES_TLS_VALIDATION_SKIPPED` and the CLI/library can switch to strict TLS validation.

### Medium

- [ ] **4. Public probe-context overrides** — library callers still cannot override IMDS/Kubernetes endpoints through the main engine API.
- [ ] **5. AppArmor vs SELinux parsing** — `SecuritySandboxProbe` still relies on a `:` heuristic that should be made robust.
- [ ] **6. Stronger OnPrem classification** — current on-prem scoring still needs better non-cloud signals.
- [ ] **7. Runtime harness coverage** — CI still lacks Podman/rootless/privileged/host-network container runs.
- [ ] **8. Parallel `/proc` reads** — `ProcFilesProbe` still reads the proc/sys file set sequentially.

### Nice To Have

- [ ] **9. Shared JSON helper** — duplicate `GetString(JsonElement, string)` helper still exists in runtime probes.
- [ ] **10. Cross-OS unit-test matrix** — CI still runs unit tests on Linux only.
- [x] **11. TODO backlog refreshed** — this file now tracks the current review backlog instead of reporting `None known`.
- [ ] **12. Stronger smoke/integration fixtures** — integration coverage still needs more real-world fixture-driven cases.

### Carry-Over

- [ ] **`SampleRegressionTests` pre-existing failure** — `docs/samples/examples/*.sample.json` files are missing from the repository. This failure predates the current review work.
- [ ] **Git history cleanup** — the early commits `Vendor curated os-release fixtures` and `Use license-safe detection map fixtures` on `feat/static-detection-map` contain GPL data in history. Consider `git rebase -i` squash/drop before merging to `main` if history cleanliness matters.
- [ ] **Override-Loader (stretch)** — `DetectionMaps.LoadOverrides(string? path)` + `--detection-map` CLI flag for user-supplied custom maps at runtime.
