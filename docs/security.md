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


## Sharing Samples

The issue prefill flow sends a dense but redacted compact sample line through the URL. This compact sample contains normalized detection signals, not raw secrets or raw host identifiers.

The full report may contain more environment-specific details. Review it before sharing.

To create a full report for upload:

```bash
docker run --pull=always --rm ghcr.io/bobiene/container-runtime-probe:latest json > my-report.json
```

Never share:

- tokens
- credentials
- private hostnames
- internal IPs
- MAC addresses
- customer names
- cloud instance IDs
- subscription/project/tenant IDs
- raw full metadata documents
- CPU serial numbers
- raw full cgroup paths with container IDs if this is sensitive in your environment

The tool must never include secrets in the issue URL.
