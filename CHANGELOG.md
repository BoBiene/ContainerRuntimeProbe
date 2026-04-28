# Changelog

## 0.1.0-preview.2 - 2026-04-28
- Added structured `Host` reporting for container image OS, visible kernel, runtime-reported host OS, hardware, and diagnostic fingerprinting.
- Added distro, architecture, kernel flavor, fingerprint mode, and fingerprint stability normalization enums.
- Added host CPU and memory parsing from `/proc` and cgroup files.
- Added runtime host enrichment from Docker `/info`, Podman `/libpod/info`, Kubernetes `status.nodeInfo`, and safe cloud metadata fields.
- Added `CRP-HOST-FP-v1` host fingerprinting with privacy-aware component selection and stable hashing.
- Updated markdown, JSON, and text renderers to include host/node reporting.
- Updated tests, examples, and docs for host reporting, privacy limitations, and fingerprint behavior.
