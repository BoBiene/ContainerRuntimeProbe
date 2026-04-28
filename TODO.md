# TODO

## Critical

All critical issues resolved. ✅

## High

All high priority issues resolved. ✅

## Medium

- [x] **Docker Compose label probe** — **DONE**
  - Implemented: `RuntimeApiProbe` now probes `/containers/{hostname}/json` after each socket.
  - Extracts 6 well-known `com.docker.compose.*` labels using AOT-safe `JsonDocument` parsing.
  - 404/403/401/timeout handled gracefully; `container.inspect.outcome` evidence emitted.
  - Tests: 4 unit tests for `ComposeLabels.ExtractFromInspectJson()`.

- [x] **Siemens IoTEdge env vars in allowlist** — **DONE**
  - Added: `IOTEDGE_MODULEID`, `IOTEDGE_DEVICEID`, `IOTEDGE_WORKLOADURI`, `IOTEDGE_APIVERSION`,
    `IOTEDGE_AUTHSCHEME`, `IOTEDGE_GATEWAYHOSTNAME` to `EnvironmentProbe.Keys`.
  - Classifier now maps IoTEdge-only evidence to `"IoTEdge"` (not `"Siemens Industrial Edge"`).
    `"Siemens Industrial Edge"` requires IoTEdge signals **plus** Siemens-specific evidence
    (key or value containing "siemens" or "industrial").
  - Tests: `Classifier_IoTEdgeAlone_DetectsIoTEdge`, `Classifier_SiemensSignalPlusSiemensIndicator_DetectsIE`.

- [x] **Kubernetes probe integration test with fake HTTPS server** — **DONE**
  - `KubernetesProbe` refactored: internal constructor injects `tokenPaths`, `namespacePaths`,
    `serviceHostOverride` for testing; production defaults unchanged.
  - 3 integration tests: `/version` success, 401 mapped as `AccessDenied`, no env → `Unavailable`.

## Low

- [x] **OpenShift classifier unit test** — **DONE**
  - Classifier check updated to accept both bare `OPENSHIFT_BUILD_NAME` and `env.OPENSHIFT_BUILD_NAME`.
  - Tests: `Classifier_OpenShift_DetectsOpenShift`, `Classifier_OpenShiftEnvPrefixed_DetectsOpenShift`.

- [x] **Dedicated SecuritySandboxProbe** — **DONE**
  - `ProcFilesProbe` no longer handles `/proc/self/status`.
  - New `SecuritySandboxProbe` (Id=`security-sandbox`) reads:
    - `/proc/self/status` → `status.Seccomp`, `status.NoNewPrivs`, `status.CapEff`, `status.CapBnd`, `status.CapPrm`
    - `/proc/self/attr/current` → `apparmor.profile` or `selinux.context` based on content format
    - `/sys/fs/selinux` directory existence → `selinux.mount.present`
  - Added to default probe set; backward-compatible evidence key names.
  - 6 unit tests added.

## Verified Done

- [x] Build succeeds with 0 warnings/errors (`dotnet build -c Release`)
- [x] All 74 tests pass (64 unit + 10 integration)
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
- [x] **FIXED**: OpenShift classifier checks both bare and `env.`-prefixed key forms
- [x] **FIXED**: IoTEdge-only → `"IoTEdge"` vendor (not `"Siemens Industrial Edge"`)
- [x] **ADDED**: Orchestrator: Azure Container Apps, Nomad, OpenShift, Cloud Run as separate from GCP
- [x] **ADDED**: Siemens IE requires specific IoTEdge+Siemens signals (compose-only = no IE)
- [x] **ADDED**: ParseCgroupSignals() with Docker v1/v2, Kubernetes, Podman, libpod signal detection
- [x] **ADDED**: `libpod` to cgroup signal patterns
- [x] **ADDED**: Docker Compose label probe (container inspect → `compose.label.*` evidence)
- [x] **ADDED**: SecuritySandboxProbe (proc/self/status, AppArmor, SELinux, /sys/fs/selinux)
- [x] **ADDED**: 22 new classifier scenario tests (all spec-required scenarios covered)
- [x] **ADDED**: 9 new redaction tests (all sensitive patterns, MaybeRedact behavior)
- [x] **ADDED**: 7 new parser cgroup tests (Docker, K8s, host-only, Podman, truncation)
- [x] **ADDED**: 6 SecuritySandboxProbe unit tests
- [x] **ADDED**: 7 new integration tests (Compose label extraction, Kubernetes fake server)
- [x] Safe local probes: `/.dockerenv`, `/run/.containerenv` (MarkerFileProbe)
- [x] Environment variables probe with allowlist and redaction (EnvironmentProbe)
- [x] Proc files probe: cgroup, mountinfo, routes, DNS, hostnames, os-release, proc/version, namespaces (ProcFilesProbe)
- [x] Security sandbox probe: Seccomp, NoNewPrivs, CapEff, AppArmor, SELinux (SecuritySandboxProbe)
- [x] Docker/Podman Unix socket probing with all required endpoints + container inspect (RuntimeApiProbe)
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

- None known.

## Final Verification Results (Second Pass)

- `dotnet restore ContainerRuntimeProbe.sln` ✅
- `dotnet build ContainerRuntimeProbe.sln -c Release` ✅ (0 warnings, 0 errors)
- `dotnet test ContainerRuntimeProbe.sln -c Release` ✅ (74/74 passed: 64 unit + 10 integration)
- `dotnet pack ContainerRuntimeProbe.sln -c Release -o artifacts/packages` ✅
- `container-runtime-probe --help` ✅
- `container-runtime-probe --list-probes` ✅ (7 probes including security-sandbox)
- `container-runtime-probe --format json --timeout 00:00:02` ✅ (Cloud=Unknown, string enums, security-sandbox evidence)
- `container-runtime-probe --format markdown --timeout 00:00:02` ✅
- `container-runtime-probe --format text --timeout 00:00:02` ✅
- `dotnet publish -p:PublishTrimmed=true -r linux-x64 --self-contained true` ✅ (0 warnings)
- `dotnet publish -p:PublishAot=true -r linux-x64 --self-contained true` ✅ (native binary functional)
- Docker: not available in CI sandbox — Docker harness tests require manual or CI execution
