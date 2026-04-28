# ContainerRuntimeProbe

.NET 8 runtime probe library + CLI for container/runtime/orchestrator/cloud evidence.

## Quick start without compiling

### Run the published preview container
Use the published GHCR image if you just want to run the probe immediately:

```bash
docker run --rm --pull=always ghcr.io/bobiene/containerruntimeprobe:preview --format json
```

With Docker socket mounted for runtime API enrichment:

```bash
docker run --rm --pull=always \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ghcr.io/bobiene/containerruntimeprobe:preview \
  --format markdown
```

Notes:
- `preview` tracks the latest preview image built from the main/develop preview workflow.
- For stable releases, prefer a version tag or `:latest` when available.
- `--pull=always` ensures you do not accidentally run an old cached image.

### Download a prebuilt binary from GitHub Releases
If you do not want Docker and do not want to build locally, download a release asset from the repository's **Releases** page:

- `container-runtime-probe-linux-x64`
- `container-runtime-probe-linux-arm64`
- `container-runtime-probe-osx-x64`
- `container-runtime-probe-osx-arm64`
- `container-runtime-probe-win-x64.exe`

Example on Linux/macOS:

```bash
chmod +x ./container-runtime-probe-linux-x64
./container-runtime-probe-linux-x64 --format json
```

### Optional: install from a downloaded .NET tool package
If you have a downloaded `ContainerRuntimeProbe.Tool.*.nupkg` package (for example from a release artifact or package feed), you can install it without compiling source:

```bash
mkdir -p ./crp-packages
cp ./ContainerRuntimeProbe.Tool.*.nupkg ./crp-packages/
dotnet tool install --global --prerelease --add-source ./crp-packages ContainerRuntimeProbe.Tool
container-runtime-probe --format json
```

## Common commands
```bash
container-runtime-probe --help
container-runtime-probe --format json
container-runtime-probe --format markdown --output report.md
container-runtime-probe --list-probes
container-runtime-probe --fingerprint safe
```

## Host OS / Node reporting
Reports separate five host-oriented views:
- **Container image OS** from `/etc/os-release` or `/usr/lib/os-release`
- **Visible kernel** from `/proc/version` and `/proc/sys/kernel/*`
- **Runtime-reported host OS** from Docker `/info`, Podman `/libpod/info`, Kubernetes `status.nodeInfo`, and safe cloud metadata fields
- **Host hardware signals** from `/proc/cpuinfo`, `/proc/meminfo`, cgroup limits, and safe runtime/cloud summaries
- **Host fingerprint** using `CRP-HOST-FP-v1` (`sha256:` over sorted normalized `key=value` lines)

Important: container image OS is not host OS. The visible kernel is an observed signal, while host OS confidence increases only when a runtime API, Kubernetes NodeInfo, or cloud metadata corroborates it.

## Contributor build / test / pack
```bash
dotnet build ContainerRuntimeProbe.sln -c Release
dotnet test ContainerRuntimeProbe.sln -c Release
dotnet pack ContainerRuntimeProbe.sln -c Release -o artifacts/packages
```

### Fingerprint modes
```bash
container-runtime-probe --fingerprint safe
container-runtime-probe --fingerprint extended
container-runtime-probe --fingerprint none
```

Default mode is `safe`. The fingerprint is for diagnostics and correlation only; it is not a security identity.

## Docker harness (verified in CI)
This section is for contributors validating the local Docker harness, not the simplest end-user path.

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
