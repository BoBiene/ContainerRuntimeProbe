# Report Format

`ContainerRuntimeReport` fields:
- `GeneratedAt`, `Duration`
- `ProbeToolInfo` with semantic `Version` and optional short `GitCommit`
- `Probes[]` with `ProbeId`, `Outcome`, `Evidence[]`, optional `Message`
- `SecurityWarnings[]`
- `Classification`
  - each dimension is a `ClassificationResult<TEnum>` carrying `Value`, `Confidence`, and `Reasons[]`
  - `Host.Family` uses `OperatingSystemFamily`
  - `Host.Type` uses `HostTypeKind`
  - `IsContainerized` uses `ContainerizationKind`
  - `ContainerRuntime` uses `ContainerRuntimeKind`
  - `Virtualization` uses `VirtualizationClassificationKind`
  - `Environment.Type` uses `EnvironmentTypeKind`
  - `RuntimeApi` uses `RuntimeApiKind`
  - `Orchestrator` uses `OrchestratorKind`
  - `CloudProvider` uses `CloudProviderKind`
  - `PlatformVendor` uses `PlatformVendorKind`
- `Host`
- `PlatformEvidence[]`
  - generic heuristic platform hypotheses keyed by `PlatformKey`
  - each entry carries `Score`, `EvidenceLevel`, `Confidence`, `Evidence[]`, and `Warnings[]`
  - `Evidence[]` uses `PlatformEvidenceItem(Type, Key, Value, Confidence, Description)`
- `TrustedPlatforms[]`
  - generic locally verifiable platform claims keyed by `PlatformKey`
  - each entry carries `State`, `VerificationLevel`, optional `VerificationMethod`, optional `Issuer`, optional `Subject`, `Claims[]`, `Evidence[]`, and `Warnings[]`
  - `Claims[]` uses `TrustedPlatformClaim(Scope, Type, Value, Confidence, Description)`
  - `Evidence[]` uses `TrustedPlatformEvidence(SourceType, Key, Value, Confidence, Description)`

## Host object
`Host` contains:
- `ContainerImageOs`
  - normalized `Family`
  - raw `/etc/os-release` identifiers (`Id`, `IdLike`, `Name`, `PrettyName`, `Version`, `VersionId`, `VersionCodename`, `BuildId`, `Variant`, `VariantId`)
  - `Architecture`, `Confidence`, `EvidenceReferences`
- `VisibleKernel`
  - `Name`, `Release`, `Version`, normalized `Architecture`, `Flavor`, `Compiler`, `Confidence`, `EvidenceReferences`
- `Virtualization`
  - normalized `Kind`, `PlatformVendor`, `Confidence`, `EvidenceReferences`
- `UnderlyingHostOs`
  - inferred `Family`, optional `Version`, `Confidence`, `EvidenceReferences`
- `RuntimeReportedHostOs`
  - trusted host/node metadata (`Family`, `Name`, `Version`, `KernelVersion`, `Architecture`, `Source`, `Confidence`, `EvidenceReferences`)
- `Hardware`
  - normalized host architecture, CPU summary, memory summary, structured public DMI fields, structured public device-tree fields, and safe cloud machine type
- `Fingerprint`
  - `Algorithm = CRP-HOST-FP-v1`
  - `Value = sha256:<lowercase hex>`
  - `Stability`, `IncludedSignalCount`, `ExcludedSensitiveSignalCount`, `Components[]`, `Warnings[]`

## Interpretation rules
- Container image OS describes the filesystem inside the container image.
- Visible kernel is an observed signal that usually reflects the host kernel.
- WSL2 kernel fingerprints map to `Virtualization.Kind = WSL2`, `Virtualization.PlatformVendor = Microsoft`, and `UnderlyingHostOs.Family = Windows`.
- `UnderlyingHostOs.Version` remains null for WSL2 because the Windows version is not derivable from the WSL2 kernel.
- Runtime-reported host OS is the highest-confidence host/node view when Docker, Podman, Kubernetes NodeInfo, or cloud metadata is available.
- Hardware is visibility-limited; cgroup limits may differ from physical host capacity.
- Fingerprints are diagnostic correlation helpers only and must not be treated as host identity.
- `PlatformEvidence` answers: "What does the observed platform look like?"
- `TrustedPlatforms` answers: "Which explicit local platform claims are strong enough to consume programmatically?"
- For the current Siemens IED flow, `TrustedPlatforms[].VerificationLevel` is monotonic: `1` artifact present, `2` artifact valid and plausible, `3` local endpoint reachable, `4` TLS binding matched.
- JSON uses the enum names emitted by `System.Text.Json`. Examples: `Containerd`, `AwsEcs`, `CloudRun`, `AzureContainerApps`, and `SiemensIndustrialEdge`.
- Markdown and text renderers keep user-facing labels such as `containerd`, `AWS ECS`, `Cloud Run`, and `Siemens Industrial Edge`.

## JSON structure (contract)
```json
{
  "GeneratedAt": "2026-04-28T00:00:00+00:00",
  "Duration": "00:00:00.123",
  "ProbeToolInfo": {
    "Version": "1.2.3",
    "GitCommit": "a1b2c3d"
  },
  "Classification": {
    "IsContainerized": { "Value": "True", "Confidence": "High", "Reasons": [] }
  },
  "PlatformEvidence": [
    {
      "PlatformKey": "siemens-industrial-edge",
      "Score": 9,
      "EvidenceLevel": "StrongHeuristic",
      "Confidence": "High",
      "Evidence": [
        {
          "Type": "ExecutionContext",
          "Key": "mountinfo.signal",
          "Value": "industrial-edge",
          "Confidence": "High",
          "Description": "Industrial Edge naming was found in local platform context."
        }
      ],
      "Warnings": []
    }
  ],
  "TrustedPlatforms": [
    {
      "PlatformKey": "siemens-ied-runtime",
      "State": "Verified",
      "VerificationMethod": "local-runtime-tls-binding",
      "Subject": "edge-iot-core.proxy-redirect",
      "Claims": [
        {
          "Scope": "RuntimePresence",
          "Type": "siemens-ied-runtime",
          "Value": "tls-bound",
          "Confidence": "High",
          "Description": "A documented local IED runtime artifact is present, reachable, and TLS-bound to documented certificate material."
        }
      ],
      "Evidence": [
        {
          "SourceType": "TlsBinding",
          "Key": "trust.ied.endpoint.tls.binding",
          "Value": "matched",
          "Confidence": "High",
          "Description": "The local IED endpoint TLS certificate matches documented certificate material."
        }
      ],
      "Warnings": [],
      "VerificationLevel": 4
    }
  ],
  "Host": {
    "ContainerImageOs": {
      "Family": "Debian",
      "Id": "debian",
      "PrettyName": "Debian GNU/Linux 12 (bookworm)",
      "Architecture": "X64",
      "Confidence": "High"
    },
    "VisibleKernel": {
      "Name": "Linux",
      "Release": "6.17.0-1011-azure",
      "Flavor": "Azure",
      "Confidence": "Medium"
    },
    "Virtualization": {
      "Kind": "Unknown",
      "PlatformVendor": null,
      "Confidence": "Unknown"
    },
    "UnderlyingHostOs": {
      "Family": "Unknown",
      "Version": null,
      "Confidence": "Unknown"
    },
    "RuntimeReportedHostOs": {
      "Source": "DockerInfo",
      "Name": "Ubuntu 24.04.4 LTS",
      "Architecture": "X64",
      "Confidence": "High"
    },
    "Hardware": {
      "Architecture": "X64",
      "Cpu": {
        "LogicalProcessorCount": 4,
        "Vendor": "GenuineIntel",
        "FlagsHash": "sha256:..."
      },
      "Memory": {
        "MemTotalBytes": 17179869184,
        "CgroupMemoryLimitRaw": "max"
      },
      "Dmi": {
        "SystemVendor": "Microsoft Corporation",
        "ProductName": "Virtual Machine",
        "ProductFamily": "Hyper-V",
        "ChassisVendor": "Microsoft Corporation"
      },
      "DeviceTree": {
        "Model": null,
        "Compatible": null
      },
      "CloudMachineType": "Standard_D4s_v5"
    },
    "Fingerprint": {
      "Algorithm": "CRP-HOST-FP-v1",
      "Value": "sha256:...",
      "Stability": "RuntimeApiBacked",
      "IncludedSignalCount": 12,
      "ExcludedSensitiveSignalCount": 2,
      "Components": [
        { "Name": "kernel.release", "Included": true, "RawValueRedacted": "6.17.0-1011-azure" }
      ],
      "Warnings": [
        "Fingerprint is diagnostic only and not a security identity."
      ]
    }
  }
}
```


## Sample export

`container-runtime-probe sample` emits a dense compact `crp1;...` line, a GitHub issue prefill URL, and optional sample JSON/Markdown output.

Compact samples are ASCII-only, URL-safe, parser-friendly, and redacted by construction. The full sample JSON wrapper adds richer redacted host, hardware, probe outcome, and signal detail for fixtures and regression tests.
