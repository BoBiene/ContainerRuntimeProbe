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

## Docker harness (verified in CI)
```bash
docker build -f docker/Dockerfile.test -t container-runtime-probe:test .
docker run --rm container-runtime-probe:test
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro container-runtime-probe:test
```

Expected output excerpts:
- markdown starts with `# Container Runtime Report`
- json contains `"Classification"` and `"Probes"`
- socket run contains `DOCKER_SOCKET_MOUNTED` warning when socket is reachable

If Docker is unavailable locally, use GitHub Actions workflow `docker-harness` and compare with samples under `docs/examples/`.

## Trim/AOT checks
```bash
# Trimmed publish (supported)
dotnet publish src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj -c Release -r linux-x64 -p:PublishTrimmed=true --self-contained true

# Native AOT attempt (best-effort, environment dependent)
dotnet publish src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj -c Release -r linux-x64 -p:PublishAot=true --self-contained true
```

## Library usage
```csharp
var engine = new RuntimeProbeEngine();
var report = await engine.RunAsync(TimeSpan.FromSeconds(2), includeSensitive: false);
```

## Security defaults
- allowlisted env vars only
- secret-pattern redaction by default
- metadata probing only for fixed allowlisted endpoints
- no credential endpoint access
- explicit warning when docker socket is visible

## Included probe families (v1)
- Safe local: markers, mountinfo, routes, DNS, hostnames, os-release, proc version, namespaces
- Security sandbox: Seccomp, NoNewPrivs, capabilities (CapEff/CapBnd/CapPrm), AppArmor profile, SELinux context
- Runtime API: Docker-compatible and Podman/Libpod Unix socket endpoints; Docker Compose label inspection
- Kubernetes: env + serviceaccount + optional API reads (`/version`, pod lookup)
- Cloud/platform: ECS metadata, AWS/Azure/GCP/OCI metadata, Cloud Run/App Service/ACA/Nomad/IoTEdge env markers

## Example reports
- in-container run (no socket): `docs/examples/report-from-container.md`, `docs/examples/report-from-container.json`
- docker-socket run plan + expected evidence: `docs/examples/report-with-docker-socket.md`, `docs/examples/report-with-docker-socket.json`

## Versioning
Current preview: `0.1.0-preview.2`. See `CHANGELOG.md`.
