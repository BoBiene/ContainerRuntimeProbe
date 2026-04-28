# Security

- No credential endpoints are queried.
- Sensitive env-like keys are redacted unless `--include-sensitive true`.
- Hostnames are redacted by default.
- Probe networking is allowlisted to known metadata routes/endpoints.
- Docker/Podman socket visibility is reported as a security warning.
- Probe failures return typed outcomes (`Unavailable`, `AccessDenied`, `Timeout`, `NotSupported`, `Error`) instead of crashing.
- Docker-socket probing is read-only (`GET` requests only).
- Host fingerprint mode defaults to `safe` and excludes hostname, container ID, pod name, instance IDs, subscription/project/tenant IDs, MAC/IP data, CPU serials, and raw overlay paths.
- CPU flags are summarized as count + hash; raw flag lists are not emitted into the fingerprint by default.
- The host fingerprint is diagnostic only and must not be used as a security identity or attestation claim.
