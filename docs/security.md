# Security

- No credential endpoints are queried.
- Sensitive env-like keys are redacted unless `--include-sensitive true`.
- Probe networking is allowlisted to known metadata routes/endpoints.
- Docker/Podman socket visibility is reported as a security warning.
- Probe failures return typed outcomes (`Unavailable`, `AccessDenied`, `Timeout`, `NotSupported`, `Error`) instead of crashing.
