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

- [x] **1. Parallel probe execution** — `ContainerRuntimeProbeEngine.RunAsync` now runs the selected probe set concurrently while preserving report order.
- [x] **2. Shared IMDS client/pooling** — `CloudMetadataProbe` now reuses one client per normalized base URI and fans out provider metadata requests concurrently.
- [x] **3. Kubernetes TLS mode** — default remains compatibility-first so in-cluster probing just works, but the report now emits `KUBERNETES_TLS_VALIDATION_SKIPPED` and the CLI/library can switch to strict TLS validation.

### Medium

- [x] **4. Public probe-context overrides** — `ProbeExecutionOptions` now exposes Kubernetes and metadata endpoint overrides on the public engine API.
- [x] **5. AppArmor vs SELinux parsing** — `SecuritySandboxProbe` now validates SELinux context shape explicitly and records `/sys/fs/selinux/enforce` evidence separately.
- [x] **6. Stronger OnPrem classification** — on-prem scoring now leans on corporate DNS, host-type corroboration, and visible default routes instead of giving cloud-metadata probe presence two free points.
- [x] **7. Runtime harness coverage** — `docker-harness.yml` now fans out across default Docker, `--privileged`, `--network host`, and rootless Podman runs.
- [x] **8. Parallel `/proc` reads** — `ProcFilesProbe` now starts the proc/sys file reads concurrently while preserving stable processing order.

### Nice To Have

- [x] **9. Shared JSON helper** — the duplicate `GetString(JsonElement, string)` logic now lives in a shared internal `JsonHelper`.
- [x] **10. Cross-OS unit-test matrix** — `ci.yml` now runs the main build-and-test job on Ubuntu, Windows, and macOS.
- [x] **11. TODO backlog refreshed** — this file now tracks the current review backlog instead of reporting `None known`.
- [x] **12. Stronger smoke/integration fixtures** — `SmokeIntegrationTests` now exercises real sample-report fixtures for proc, mountinfo, os-release, and WSL2-specific signals.

### Carry-Over

- [ ] **`SampleRegressionTests` pre-existing failure** — `docs/samples/examples/*.sample.json` files are missing from the repository. This failure predates the current review work.
- [ ] **Git history cleanup** — the early commits `Vendor curated os-release fixtures` and `Use license-safe detection map fixtures` on `feat/static-detection-map` contain GPL data in history. Consider `git rebase -i` squash/drop before merging to `main` if history cleanliness matters.
- [ ] **Override-Loader (stretch)** — `DetectionMaps.LoadOverrides(string? path)` + `--detection-map` CLI flag for user-supplied custom maps at runtime.
