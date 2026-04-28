# Report Format

`ContainerRuntimeReport` fields:
- `GeneratedAt`, `Duration`
- `Probes[]` with `ProbeId`, `Outcome`, `Evidence[]`, optional `Message`
- `SecurityWarnings[]`
- `Classification`
- `Host`

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
  - normalized host architecture, CPU summary, memory summary, and safe cloud machine type
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

## JSON structure (contract)
```json
{
  "GeneratedAt": "2026-04-28T00:00:00+00:00",
  "Duration": "00:00:00.123",
  "Classification": {
    "IsContainerized": { "Value": "True", "Confidence": "High", "Reasons": [] }
  },
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
