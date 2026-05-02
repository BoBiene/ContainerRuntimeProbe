# Changelog

## Unreleased
- Added conservative `CloudEnvironmentIdentity`, `TpmPublicKeyDigest`, and `HypervisorIdentity` anchor paths to cover provider-boundary environment IDs, visible TPM public material, and guest-visible VM UUIDs.
- Preserved weaker fallback identities alongside stronger same-scope anchors in `IdentityAnchors` and summary output so L3/L2/L1 candidates can be reported together.
- Expanded identity documentation, matrix coverage, and tests for stacked host, workload, deployment, and Kubernetes node identities.

## 0.1.0-preview.2 - 2026-04-28
- Added structured `Host` reporting for container image OS, visible kernel, runtime-reported host OS, hardware, diagnostic fingerprints, and redacted identity anchors.
- Added distro, architecture, kernel flavor, fingerprint mode, and fingerprint stability normalization enums.
- Added host CPU and memory parsing from `/proc` and cgroup files.
- Added runtime host enrichment from Docker `/info`, Podman `/libpod/info`, Kubernetes `status.nodeInfo`, and safe cloud metadata fields.
- Added `CRP-HOST-FP-v1` host fingerprinting with privacy-aware component selection and stable hashing.
- Added digested cloud-instance and Kubernetes-node identity anchors with default redaction in the safe report path.
- Updated markdown, JSON, and text renderers to include host/node reporting.
- Updated tests, examples, and docs for host reporting, privacy limitations, and fingerprint behavior.
