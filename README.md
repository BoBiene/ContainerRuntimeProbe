# ContainerRuntimeProbe

.NET 8 runtime probe library + CLI for container/runtime/orchestrator/cloud evidence.

## Build / Test / Pack
```bash
dotnet build ContainerRuntimeProbe.sln -c Release
dotnet test ContainerRuntimeProbe.sln -c Release
dotnet pack ContainerRuntimeProbe.sln -c Release -o artifacts/packages
```

## Install and run tool locally
```bash
dotnet tool install --global --prerelease --add-source ./artifacts/packages ContainerRuntimeProbe.Tool
container-runtime-probe --help
container-runtime-probe --format json
container-runtime-probe --format markdown --output report.md
container-runtime-probe --list-probes
```

## Host OS / Node reporting
Reports now separate five host-oriented views:
- **Container image OS** from `/etc/os-release` or `/usr/lib/os-release`
- **Visible kernel** from `/proc/version` and `/proc/sys/kernel/*`
- **Runtime-reported host OS** from Docker `/info`, Podman `/libpod/info`, Kubernetes `status.nodeInfo`, and safe cloud metadata fields
- **Host hardware signals** from `/proc/cpuinfo`, `/proc/meminfo`, cgroup limits, and safe runtime/cloud summaries
- **Host fingerprint** using `CRP-HOST-FP-v1` (`sha256:` over sorted normalized `key=value` lines)

Important: container image OS is not host OS. The visible kernel is an observed signal, while host OS confidence increases only when a runtime API, Kubernetes NodeInfo, or cloud metadata corroborates it.

### Fingerprint modes
```bash
container-runtime-probe --fingerprint safe
container-runtime-probe --fingerprint extended
container-runtime-probe --fingerprint none
```

Default mode is `safe`. The fingerprint is for diagnostics and correlation only; it is not a security identity.

## Docker harness (verified in CI)
```bash
docker build -f docker/Dockerfile.test -t container-runtime-probe:test .
docker run --rm container-runtime-probe:test
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro container-runtime-probe:test
```

Expected output excerpts:
- markdown starts with `# Container Runtime Report`
- markdown includes `## Host OS / Node`
- json contains `"Classification"`, `"Host"`, and `"Probes"`
- socket run contains `DOCKER_SOCKET_MOUNTED` warning when socket is reachable

If Docker is unavailable locally, use GitHub Actions workflow `docker-harness` and compare with samples under `docs/examples/`.

## Trim/AOT checks
```bash
# Trimmed publish (supported)
dotnet publish src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj -c Release -r linux-x64 -p:PublishTrimmed=true --self-contained true

# Native AOT attempt (best-effort, environment dependent)
dotnet publish src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj -c Release -r linux-x64 -p:PublishAot=true --self-contained true
```

## Security defaults
- allowlisted env vars only
- secret-pattern redaction by default
- hostname redaction by default unless `--include-sensitive true`
- metadata probing only for fixed allowlisted endpoints
- no credential endpoint access
- host fingerprint excludes hostname, container ID, pod name, instance IDs, project IDs, tenant IDs, MAC/IP data, CPU serials, and raw overlay paths
- explicit warning when docker socket is visible

## Included probe families (v1)
- Safe local: markers, mountinfo, routes, DNS, hostnames, os-release, kernel, CPU, memory, namespaces
- Security sandbox: Seccomp, NoNewPrivs, capabilities (CapEff/CapBnd/CapPrm), AppArmor profile, SELinux context
- Runtime API: Docker-compatible and Podman/Libpod Unix socket endpoints; Docker Compose label inspection
- Kubernetes: env + serviceaccount + `/version`, pod lookup, optional node lookup for `status.nodeInfo`
- Cloud/platform: ECS metadata, AWS/Azure/GCP/OCI metadata, Cloud Run/App Service/ACA/Nomad/IoTEdge env markers

## Example reports
- in-container run (no socket): `docs/examples/report-from-container.md`, `docs/examples/report-from-container.json`
- docker-socket run: `docs/examples/report-with-docker-socket.md`, `docs/examples/report-with-docker-socket.json`

## Versioning
Current preview: `0.1.0-preview.2`. See `CHANGELOG.md`.
