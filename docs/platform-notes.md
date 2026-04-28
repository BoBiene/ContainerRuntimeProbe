# Platform Notes

- Linux-first probing uses `/proc`, `/sys`, and `/etc` signals.
- Container image OS and host OS are intentionally reported separately.
- Visible kernel data usually reflects the host kernel, but it remains an observed signal rather than a guaranteed host identity.
- Docker and Podman host OS confidence improves when `/info` or `/libpod/info` succeeds.
- Kubernetes host OS confidence improves when pod lookup can be followed by node lookup and `status.nodeInfo` is readable.
- Cloud metadata host enrichment is best-effort and limited to safe machine-type / region / zone style fields.
- Hardware summaries reflect what is visible inside the current container and may be constrained by cgroups.
- Native AOT publish is environment/toolchain dependent; trimmed publish is validated in CI via `publish-check`.
