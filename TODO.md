# TODO

## Critical

All critical issues resolved. ✅

## High

- [ ] **Missing classifier scenario tests for bounded ECS key prefix**
  - Problem: `ecs.` key prefix in cloud classifier checks `x.Key.StartsWith("ecs.")` — this is an
    evidence key from cloud-metadata probe that should have format `ecs.<path>.outcome`. Existing tests
    pass `ecs.task.outcome` correctly.
  - Status: **Verified working** in `Classifier_EcsMetadataSuccess_DetectsAwsEcsOrchestrator` test.

- [ ] **Missing `/proc/self/status` dedicated security probe test**
  - Problem: `ProcFilesProbe` reads Seccomp/NoNewPrivs/CapEff from `/proc/self/status` but there is no
    unit test asserting these fields appear in output. The parsing is covered by the integration smoke test.
  - Fix: Add a test with a fake `/proc/self/status` content if feasible, or verify via the engine test.
  - Status: **Low priority** — partially covered by `EngineAndRendererTests.RunAsync_ProducesReport`

- [ ] **Docker Compose label probe not implemented**
  - Problem: The spec requires Docker Compose label discovery via Docker API container inspection. The
    current `RuntimeApiProbe` queries `/info` but does not inspect the current container's labels.
  - Fix: When Docker socket is available and `/info` succeeds, optionally query
    `/containers/{hostname}/json` to get labels and check for `com.docker.compose.*` labels.
  - Verify: Integration test with fake Docker API returning compose labels.
  - Status: **Open — Medium priority**

- [ ] **Siemens Industrial Edge: no dedicated IoTEdge socket probe**
  - Problem: The classifier checks for "iotedge" in evidence values but no probe actually tries
    `/var/run/iotedge.sock`. The env var `IOTEDGE_MODULEID` is not in the environment probe's allowlist.
  - Fix: Add `IOTEDGE_MODULEID` and `IOTEDGE_DEVICEID` to `EnvironmentProbe.Keys`.
  - Verify: Test that IoTEdge module ID in env triggers Siemens IE classification.
  - Status: **Open — Medium priority**

- [ ] **Integration tests: missing Kubernetes probe fake endpoint test**
  - Problem: Only CloudMetadata and smoke tests exist. Kubernetes probe has no fake HTTPS server test.
  - Fix: Add `KubernetesProbeIntegrationTests.cs` with a fake HTTPS server.
  - Verify: Tests pass.
  - Status: **Open — Medium priority**

## Medium

- [ ] **Cgroup v1/v2 CPU/memory limit values not parsed**
  - Problem: Cgroup limit files (`/sys/fs/cgroup/memory.max`) are read as raw evidence but not
    parsed into human-readable limit values. The evidence key includes the full path.
  - Status: **Partially done** — raw values captured; human-readable parsing deferred.

- [ ] **`/proc/self/status` security probe could be a dedicated probe**
  - Problem: Security fields (Seccomp, NoNewPrivs, CapEff) are embedded in ProcFilesProbe. A
    dedicated `SecuritySandboxProbe` would improve probe filtering.
  - Status: **Low priority — tracked for future version**

- [ ] **OpenShift detection has no unit test**
  - Problem: `OPENSHIFT_BUILD_NAME/NAMESPACE` env vars are in the environment probe allowlist and
    in the classifier, but no test covers the OpenShift classification path.
  - Fix: Add a classifier test for OpenShift env vars.
  - Status: **Open — Low priority**

## Low

- [ ] **`--format` unknown value could show available formats in error message**
  - Problem: Error says `--format must be one of: json|markdown|text` but only shows this in --help.
    Error message at runtime is brief.
  - Status: **Already improved** — exit code 2 now returned with clear message.

- [ ] **`ReportRenderer.ToText` is a single line**
  - Status: **Low priority — intentional compact format for scripting use**

## Verified Done

- [x] Build succeeds with 0 warnings/errors (`dotnet build -c Release`)
- [x] All 55 tests pass (53 unit + 2 integration)
- [x] CLI tool produces output for `--help`, `--list-probes`, `--format json/markdown/text`
- [x] `dotnet pack` succeeds, NuGet metadata is present
- [x] **FIXED**: Classifier cloud false positive — Cloud=Unknown on non-cloud environments
- [x] **FIXED**: Classifier containerReasons pollution by AddRuntime() — separate reasons per dimension
- [x] **FIXED**: JSON enum serialization — enums now serialize as strings (UseStringEnumConverter=true)
- [x] **FIXED**: Repository URLs updated from `example` to `BoBiene` in all project files
- [x] **FIXED**: `/proc/1/cgroup` and `/proc/self/cgroup` now probed with ParseCgroupSignals()
- [x] **FIXED**: `/usr/lib/os-release` fallback added (skipped if `/etc/os-release` already succeeded)
- [x] **FIXED**: Bounded file reads — 256 KB cap via streaming FileStream instead of ReadAllTextAsync
- [x] **FIXED**: Podman socket discovery — uses XDG_RUNTIME_DIR or enumerates /run/user/ instead of UID env
- [x] **FIXED**: `--format` invalid value returns exit code 2 (not 1)
- [x] **ADDED**: Orchestrator: Azure Container Apps, Nomad, OpenShift, Cloud Run as separate from GCP
- [x] **ADDED**: Siemens IE requires specific IoTEdge/Siemens signals (compose-only = no IE classification)
- [x] **ADDED**: ParseCgroupSignals() with Docker v1/v2, Kubernetes, Podman, libpod signal detection
- [x] **ADDED**: `libpod` to cgroup signal patterns
- [x] **ADDED**: 22 new classifier scenario tests (all spec-required scenarios covered)
- [x] **ADDED**: 9 new redaction tests (all sensitive patterns, MaybeRedact behavior)
- [x] **ADDED**: 7 new parser cgroup tests (Docker, K8s, host-only, Podman, truncation)
- [x] Safe local probes: `/.dockerenv`, `/run/.containerenv` (MarkerFileProbe)
- [x] Environment variables probe with allowlist and redaction (EnvironmentProbe)
- [x] Proc files probe: cgroup, mountinfo, routes, DNS, hostnames, os-release, proc/version, status, namespaces (ProcFilesProbe)
- [x] Docker/Podman Unix socket probing with all required endpoints (RuntimeApiProbe)
- [x] Kubernetes env + serviceaccount + API probing (KubernetesProbe)
- [x] Cloud metadata: ECS, AWS IMDSv2, Azure IMDS, GCP, OCI, env markers (CloudMetadataProbe)
- [x] Weighted classifier with 6 dimensions: IsContainerized, ContainerRuntime, RuntimeApi, Orchestrator, CloudProvider, PlatformVendor
- [x] JSON, Markdown, Text renderers
- [x] Security warnings (DOCKER_SOCKET_MOUNTED)
- [x] System.Text.Json source generation (`ReportJsonContext`)
- [x] XML docs on public API
- [x] Nullable enabled + warnings as errors (0 warnings in build)
- [x] MIT LICENSE present
- [x] CHANGELOG.md present
- [x] Docker harness (`Dockerfile.test`, `docker-compose.yml`)
- [x] GitHub Actions workflows (build, test, pack, release, docker-harness, publish-check)
- [x] Docs: probe-catalog.md, report-format.md, security.md, platform-notes.md, examples/
- [x] Sensitive key redaction by default, opt-in `--include-sensitive`
- [x] No credentials in any output by default
- [x] Fixed allowlist for metadata endpoint probing (no arbitrary URLs)
- [x] No mutation of any runtime API
- [x] **Trimmed publish**: `dotnet publish -p:PublishTrimmed=true --self-contained true` ✅ (no warnings)
- [x] **Native AOT publish**: `dotnet publish -p:PublishAot=true --self-contained true` ✅ (native binary works)

## Final Open Points

- Docker Compose label probe via container inspection (Medium)
- Siemens IoTEdge env vars in allowlist (Medium)
- Kubernetes integration test with fake HTTPS server (Medium)
- OpenShift classifier unit test (Low)
- Dedicated security sandbox probe (Low)

## Final Verification Results

- `dotnet restore ContainerRuntimeProbe.sln` ✅
- `dotnet build ContainerRuntimeProbe.sln -c Release` ✅ (0 warnings, 0 errors)
- `dotnet test ContainerRuntimeProbe.sln -c Release` ✅ (55/55 passed: 53 unit + 2 integration)
- `dotnet pack ContainerRuntimeProbe.sln -c Release -o artifacts/packages` ✅
- `container-runtime-probe --help` ✅
- `container-runtime-probe --list-probes` ✅ (6 probes)
- `container-runtime-probe --format json --timeout 00:00:02` ✅ (Cloud=Unknown, string enums)
- `container-runtime-probe --format markdown --timeout 00:00:02` ✅
- `container-runtime-probe --format text --timeout 00:00:02` ✅
- `dotnet publish -p:PublishTrimmed=true -r linux-x64 --self-contained true` ✅
- `dotnet publish -p:PublishAot=true -r linux-x64 --self-contained true` ✅ (native binary functional)
