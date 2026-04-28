# Platform Notes

- Linux-first probing using `/proc` and `/etc` signals.
- Docker vs Podman is derived from socket endpoint behavior and returned payloads.
- Kubernetes API calls may return 401/403 depending on RBAC and are recorded as evidence.
- Cloud metadata is best-effort and safe-path only.
- Siemens Industrial Edge is intentionally conservative and only classified when Siemens-specific signals exist.
- Native AOT publish is environment/toolchain dependent (requires native toolchain); trimmed publish is validated in CI via `publish-check` workflow.
