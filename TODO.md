# TODO

## Critical

- [ ] **Classifier cloud detection always returns Azure**
  - Problem: `CloudMetadataProbe` always adds `azure.imds.outcome`, `gcp.metadata.outcome`, `oci.metadata.outcome`
    evidence keys even when the probe fails (Unavailable/Timeout). The classifier checks `e.Any(x => x.Key.StartsWith("azure."))`
    which always matches, making Azure win regardless of environment.
  - Fix: Check that the evidence *value* is `"Success"` before attributing cloud classification.
  - Verify: `dotnet run ... --format json --timeout 00:00:02 | jq .Classification.CloudProvider` should show
    `"Unknown"` (not `"Azure"`) in a non-Azure environment such as GitHub Actions.
  - Status: **Open**

- [ ] **Classifier ContainerReasons list polluted by AddRuntime()**
  - Problem: `AddRuntime()` appends to `containerReasons` instead of a separate `runtimeReasons` list.
    `ContainerRuntime` classification then has misleading reasons (Docker/Podman reasons shown for container reasons).
  - Fix: Use a separate `List<ClassificationReason>` for runtime reasons.
  - Verify: Unit test asserting `IsContainerized.Reasons` does not contain runtime API reasons.
  - Status: **Open**

- [ ] **JSON enums serialized as integers**
  - Problem: `ProbeOutcome`, `Confidence`, `EvidenceSensitivity` enums serialize as `0`, `1`, `2` in JSON output.
    Makes the JSON report unreadable without docs.
  - Fix: Add `[JsonConverter(typeof(JsonStringEnumConverter<>))]` or use `UseStringEnumConverter = true` in the
    `JsonSourceGenerationOptions` attribute.
  - Verify: `dotnet run ... --format json | grep '"Outcome"'` should show `"Success"` not `0`.
  - Status: **Open**

## High

- [ ] **Missing `/proc/1/cgroup` and `/proc/self/cgroup` probes**
  - Problem: Cgroup files are not read. These are key signals for detecting Docker containers (path contains
    `/docker/<id>`), Kubernetes pods (`/kubepods/...`), and Podman containers.
  - Fix: Add both files to `ProcFilesProbe`, parse for container-like cgroup paths as signals.
  - Verify: Running inside a Docker container should produce cgroup evidence with `/docker/` prefix.
  - Status: **Open**

- [ ] **Missing `/usr/lib/os-release` fallback**
  - Problem: Only `/etc/os-release` is probed. On some systems (e.g., Gentoo, some minimal containers) only
    `/usr/lib/os-release` exists.
  - Fix: Try `/etc/os-release` first, then `/usr/lib/os-release` as fallback.
  - Verify: Test with both files absent, one present, and both present.
  - Status: **Open**

- [ ] **Unbounded file reads**
  - Problem: `ProbeIo.ReadFileAsync` uses `File.ReadAllTextAsync` without size limits. On systems with many
    mounts, `/proc/self/mountinfo` can be very large. If something unusual happens, this could cause memory issues.
  - Fix: Add a `maxBytes` parameter (e.g., 256 KB default) and read only up to that limit.
  - Verify: Write a unit test with a large fake file.
  - Status: **Open**

- [ ] **Podman socket UID discovery uses unset env var**
  - Problem: `Environment.GetEnvironmentVariable("UID")` returns `null` in most .NET processes (UID is a
    shell variable, not an exported env var). The code falls back to `"0"` which is incorrect for non-root users.
  - Fix: Enumerate `/run/user/` directory entries and check for podman sockets, or use
    `System.Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR")` as a hint.
  - Verify: Running as non-root user should discover `/run/user/<uid>/podman/podman.sock`.
  - Status: **Open**

- [ ] **Repository URLs still say `example` in .csproj and Directory.Build.props**
  - Problem: `PackageProjectUrl` and `RepositoryUrl` point to `https://github.com/example/ContainerRuntimeProbe`.
    This will be wrong in published NuGet packages.
  - Fix: Update to `https://github.com/BoBiene/ContainerRuntimeProbe`.
  - Verify: `dotnet pack` then inspect `.nupkg` metadata.
  - Status: **Open**

- [ ] **Cloud classifier assigns success based on env keys only for some clouds**
  - Problem: The GCP check uses `e.Any(x => x.Key == "env.K_SERVICE")` which would set cloud to `GoogleCloud`
    and `Orchestrator` to `Cloud Run`. These two should be decoupled (Cloud Run runs on GCP, but cloud provider
    and orchestrator are separate dimensions).
  - Fix: GCP cloud should only be set on successful metadata probe outcome. Cloud Run orchestrator should
    remain its own signal.
  - Verify: Test scenario with K_SERVICE set but no GCP metadata → `Cloud=Unknown`, `Orchestrator=Cloud Run`.
  - Status: **Open**

- [ ] **Missing classifier scenario tests**
  - Problem: Several required scenarios from the spec are not tested:
    - Marker file only → containerized Low confidence, runtime Unknown
    - Docker socket + `/version` body containing "Docker" → Docker high confidence
    - Podman identifiers in API response → ContainerRuntime=Podman, RuntimeApi=PodmanLibpod
    - ECS metadata Success → AWS ECS high confidence
    - Azure Container Apps env markers → Azure Container Apps classification
    - Siemens Industrial Edge: weak Docker Compose evidence only → no IE classification
    - Siemens: Siemens-specific + Compose evidence → IE medium/high confidence
  - Fix: Add parameterized classifier scenario tests.
  - Verify: All new tests pass.
  - Status: **Open**

- [ ] **Missing redaction unit tests**
  - Problem: `Redaction.IsSensitiveKey` and `MaybeRedact` have no dedicated tests. A regression could expose
    secrets in output.
  - Fix: Add `RedactionTests.cs` covering sensitive patterns and the `includeSensitive` flag.
  - Verify: Tests pass.
  - Status: **Open**

## Medium

- [ ] **Cgroup v1/v2 CPU/memory limit parsing not implemented**
  - Problem: The spec requires "cgroup v1/v2 limits where practical". Currently only cgroup file paths are read,
    not parsed for limit values.
  - Fix: Parse `/sys/fs/cgroup/memory/memory.limit_in_bytes` (v1) and `/sys/fs/cgroup/memory.max` (v2) as evidence.
  - Verify: Running inside a resource-constrained container should surface memory limits.
  - Status: **Open**

- [ ] **Docker Compose label probe not implemented**
  - Problem: The spec requires Docker Compose label discovery via Docker API container inspection. The current
    `RuntimeApiProbe` queries `/info` but does not inspect the current container's labels.
  - Fix: When Docker socket is available and `/info` succeeds, optionally query
    `/containers/self/json` or use `HOSTNAME` as container ID to inspect labels.
  - Verify: Integration test with fake Docker API returning compose labels.
  - Status: **Open**

- [ ] **Siemens Industrial Edge: no dedicated probe signals**
  - Problem: The classifier checks for strings "industrial" or "siemens" in evidence, but no probe actually
    collects IE-specific signals (specific socket paths, image labels, env vars).
  - Fix: Add IE-specific heuristics: check for `/var/run/iotedge.sock` or env `IOTEDGE_MODULEID`, and
    treat presence of Docker Compose labels with `com.siemens.` prefix as corroboration.
  - Verify: Unit test with fake evidence → IE Medium confidence only when both signals present.
  - Status: **Open**

- [ ] **Security probe family missing**
  - Problem: The spec mentions "Security/sandbox probes" as a probe family to validate. Currently
    `/proc/self/status` is partially read (Seccomp, NoNewPrivs, CapEff) but there is no dedicated
    `SecuritySandboxProbe` and no test for it.
  - Fix: Extract security fields from `ProcFilesProbe` into a dedicated probe or ensure coverage is tested.
  - Verify: Test that Seccomp/NoNewPrivs/CapEff evidence is produced.
  - Status: **Open**

- [ ] **Integration tests: missing Kubernetes probe and RuntimeApiProbe fake tests**
  - Problem: Only CloudMetadata and smoke tests exist. Kubernetes probe and RuntimeApiProbe (Docker/Podman
    socket) have no fake endpoint integration tests.
  - Fix: Add `KubernetesProbeIntegrationTests.cs` with a fake HTTPS server returning Kubernetes API responses.
  - Verify: Tests pass.
  - Status: **Open**

- [ ] **`--format` argument error message not helpful**
  - Problem: An invalid format (`--format xml`) produces an `ArgumentException` from `switch` but the message
    says "must be one of: json|markdown|text" which is OK, but the exit code is `1` (generic exception path)
    not `2` (argument error path).
  - Fix: Catch the invalid format case before calling render, return exit code `2`.
  - Verify: `container-runtime-probe --format xml; echo $?` should print `2`.
  - Status: **Open**

## Low

- [ ] **`/proc/self/ns/*` uses `FileInfo.LinkTarget` which may not work on all platforms**
  - Problem: `new FileInfo(path).LinkTarget` resolves symlinks. On non-Linux or some restricted environments,
    this may throw or return null silently.
  - Fix: Add try/catch (already done) but also handle the null `LinkTarget` case more clearly.
  - Verify: Current code already catches exceptions but `target ?? "unknown"` is already handled.
  - Status: **Low priority - already partially handled**

- [ ] **`ReportRenderer.ToText` is a single line with no newline separation**
  - Problem: The text format is extremely compact and loses structure. For multi-line diagnostics the text
    format should at least have probe-level lines.
  - Fix: Consider making `ToText` output a multi-line summary block.
  - Verify: `dotnet run ... --format text` produces something readable.
  - Status: **Low priority**

- [ ] **No evidence of OpenShift detection in classifier**
  - Problem: `OPENSHIFT_BUILD_NAME` and `OPENSHIFT_BUILD_NAMESPACE` are captured in environment probe but
    never contribute to orchestrator classification.
  - Fix: Add OpenShift orchestrator weight to classifier.
  - Verify: Test with OpenShift env vars → `Orchestrator=OpenShift`.
  - Status: **Open**

## Verified Done

- [x] Build succeeds with 0 warnings/errors (`dotnet build -c Release`)
- [x] All 11 tests pass (9 unit + 2 integration)
- [x] CLI tool produces output for `--help`, `--list-probes`, `--format json/markdown/text`
- [x] `dotnet pack` succeeds, NuGet metadata is present
- [x] Safe local probes: `/.dockerenv`, `/run/.containerenv` (MarkerFileProbe)
- [x] Environment variables probe with allowlist and redaction (EnvironmentProbe)
- [x] Proc files probe: mountinfo, routes, DNS, hostnames, os-release, proc/version, status, namespaces (ProcFilesProbe)
- [x] Docker/Podman Unix socket probing with `/_ping`, `/version`, `/info`, `/libpod/*` (RuntimeApiProbe)
- [x] Kubernetes env + serviceaccount + API probing (KubernetesProbe)
- [x] Cloud metadata: ECS, AWS IMDSv2, Azure IMDS, GCP, OCI, env markers (CloudMetadataProbe)
- [x] Weighted classifier with 6 dimensions: IsContainerized, ContainerRuntime, RuntimeApi, Orchestrator, CloudProvider, PlatformVendor
- [x] JSON, Markdown, Text renderers
- [x] Security warnings (DOCKER_SOCKET_MOUNTED)
- [x] `CancellationToken` support throughout
- [x] Bounded timeout via `CancellationTokenSource.CancelAfter`
- [x] System.Text.Json source generation (`ReportJsonContext`)
- [x] XML docs on public API
- [x] Nullable enabled + warnings as errors (0 warnings in build)
- [x] Deterministic builds, SourceLink configured
- [x] MIT LICENSE present
- [x] CHANGELOG.md present
- [x] Docker harness (`Dockerfile.test`, `docker-compose.yml`)
- [x] GitHub Actions workflows (build, test, pack, release, docker-harness, publish-check)
- [x] Docs: probe-catalog.md, report-format.md, security.md, platform-notes.md, examples/
- [x] Sensitive key redaction by default, opt-in `--include-sensitive`
- [x] No credentials in any output by default
- [x] Fixed allowlist for metadata endpoint probing (no arbitrary URLs)
- [x] No mutation of any runtime API

## Verification Results (Step 2 baseline)

- `dotnet restore ContainerRuntimeProbe.sln` ✅ (all 4 projects restored)
- `dotnet build ContainerRuntimeProbe.sln -c Release` ✅ (0 warnings, 0 errors)
- `dotnet test ContainerRuntimeProbe.sln -c Release` ✅ (11/11 passed)
- `dotnet pack ContainerRuntimeProbe.sln -c Release -o artifacts/packages` ✅
- `container-runtime-probe --help` ✅
- `container-runtime-probe --list-probes` ✅ (6 probes: marker-files, environment, proc-files, runtime-api, kubernetes, cloud-metadata)
- `container-runtime-probe --format json --timeout 00:00:02` ✅ (but cloud=Azure false positive - see Critical)
- `container-runtime-probe --format markdown --timeout 00:00:02` ✅
- `container-runtime-probe --format text --timeout 00:00:02` ✅

## Open TODO Count by Priority (after initial audit)

- Critical: 3
- High: 7
- Medium: 5
- Low: 3
- Total: 18
