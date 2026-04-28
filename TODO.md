# TODO

## Open points review

- [x] **1. Parallel probe execution**
  - `ContainerRuntimeProbeEngine` now awaits probes via `Task.WhenAll`.
  - Added a regression test that verifies multiple delayed probes finish in parallel.

- [x] **2. Shared IMDS connection pooling**
  - AWS, Azure, and OCI now reuse shared HTTP handlers for the default `169.254.169.254` metadata endpoint.
  - Added coverage for shared handler reuse.

- [x] **3. Explicit Kubernetes TLS validation**
  - Kubernetes certificate validation now stays enabled by default.
  - TLS skipping is opt-in and emits a report-level `SecurityWarning`.

- [x] **4. Public endpoint override API**
  - Added `ProbeRunOptions` so library callers can override Kubernetes and IMDS base URIs.
  - Endpoint override behavior is covered by integration tests.

- [x] **5. Robust AppArmor vs SELinux detection**
  - `SecuritySandboxProbe` now validates SELinux contexts more carefully and records SELinux enforcement state when available.

- [x] **6. Stronger `OnPrem` classification**
  - Removed the free `cloud-metadata` score boost.
  - Added DMI vendor and managed DNS signals to improve `OnPrem` detection.

- [x] **7. Broader container harness CI**
  - Docker harness now exercises default, privileged, host-network, rootless-Docker, and Podman scenarios.

- [x] **8. Parallel `/proc` reads**
  - `ProcFilesProbe` now starts file reads concurrently while preserving the existing parsing flow and `/etc/os-release` fallback behavior.

- [x] **9. Shared JSON helper**
  - Consolidated duplicated `GetString()` JSON access logic into `JsonHelper`.

- [x] **10. Cross-platform CI**
  - CI now runs unit tests on Linux, Windows, and macOS, with Linux retaining the full integration suite.

- [x] **11. Maintain the open-points list**
  - This file now tracks the reviewed points and their completion status instead of reporting “None known”.

- [x] **12. Fixture-based integration coverage**
  - Added sample report fixtures for WSL2 and macOS scenarios.
  - Added parser integration fixtures for Docker, Kubernetes, Podman, and WSL2 inputs.

## Validation

- [x] `dotnet build ContainerRuntimeProbe.sln -c Release`
- [x] `dotnet test ContainerRuntimeProbe.sln -c Release --no-build`

## Newly discovered open points

- None currently known.
