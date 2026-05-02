# Report Format

`ContainerRuntimeReport` fields:
- `GeneratedAt`, `Duration`
- `ProbeToolInfo` with semantic `Version` and optional short `GitCommit`
- `Summary`
  - top-level structured summary composed of `Environment` and `Identity`
  - `Environment.Sections[]` uses `EnvironmentSummarySection(Kind, Title, Facts)`
  - `Identity.Sections[]` uses `IdentitySummarySection(Kind, Title, Facts)`
  - each `SummaryFact` carries `Label`, `Value`, `Scope`, optional `Level`, `Confidence`, optional `SourceKind`, `Usage`, and optional `EvidenceKeys[]`
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
  - current built-in keys are `siemens-ied-runtime`, `windows-host-tpm`, and `container-tpm-visible`

## Host object
`Host` contains:
- `ContainerImageOs`
  - normalized `Family`
  - raw `/etc/os-release` identifiers (`Id`, `IdLike`, `Name`, `PrettyName`, `Version`, `VersionId`, `VersionCodename`, `BuildId`, `Variant`, `VariantId`)
  - `Architecture`, `Confidence`, `EvidenceReferences`
- `VisibleKernel`
  - `IdentityAnchors`
    - explicit digest-based identity anchors separate from diagnostic fingerprints
    - current built-in kinds are `CloudInstanceIdentity`, `KubernetesNodeIdentity`, `VendorRuntimeIdentity`, `MachineIdDigest`, `HardwareIdentity`, and `ContainerRuntimeIdentity`
    - the current `VendorRuntimeIdentity` path is limited to Siemens IED certificate-chain evidence with matched local TLS binding
    - the current `MachineIdDigest` path is limited to local Windows `MachineGuid` or Linux `machine-id` values and is intentionally classified as a conservative host-correlation anchor outside containerized environments
    - the current `HardwareIdentity` path is limited to explicit host-visible hardware identifiers such as SMBIOS UUIDs or serials, device-tree or SoC serials, and CPU serials when they are directly visible
    - the current `ContainerRuntimeIdentity` path is limited to explicit runtime inspect container IDs and is intentionally scoped to workload correlation rather than host binding
    - default safe rendering keeps the anchor metadata but redacts the sensitive anchor value unless sensitive output is explicitly enabled
  - `Name`, `Release`, `Version`, normalized `Architecture`, `Flavor`, `Compiler`, `Confidence`, `EvidenceReferences`
- `Virtualization`
  - normalized `Kind`, `PlatformVendor`, `Confidence`, `EvidenceReferences`
- `UnderlyingHostOs`
  - inferred `Family`, optional `Version`, `Confidence`, `EvidenceReferences`
- `RuntimeReportedHostOs`
  - trusted host/node metadata (`Family`, `Name`, `Version`, `KernelVersion`, `Architecture`, `Source`, `Confidence`, `EvidenceReferences`)
- `Hardware`
  - normalized host architecture, CPU summary, memory summary, structured public DMI fields, structured public device-tree fields, and safe cloud machine type
- `DiagnosticFingerprints[]`
  - diagnostic-only fingerprints for environment correlation and profiling
  - current first built-in entry continues to use `Algorithm = CRP-HOST-FP-v1`
  - each entry carries `Purpose`, `Algorithm`, `Value`, legacy `Stability`, `StabilityLevel`, `UniquenessLevel`, `CorroborationLevel`, `SourceClasses[]`, `IncludedSignalCount`, `ExcludedSensitiveSignalCount`, `Components[]`, `Warnings[]`, and `Reasons[]`
- `IdentityAnchors[]`
  - explicit read-only anchor candidates for stronger host or workload binding scenarios
  - each entry carries `Kind`, `Algorithm`, `Value`, `Scope`, `BindingSuitability`, `Strength`, `Sensitivity`, `EvidenceReferences[]`, `Warnings[]`, and `Reasons[]`
  - current built-in sources are cloud instance identity metadata, Kubernetes node identity metadata, Siemens IED runtime certificate-chain identity, host machine-id style digests, explicit hardware identifier digests, and explicit runtime inspect container IDs
  - `Value` is a digest, not the raw observed instance ID or node ID
  - anchor generation is intentionally conservative; empty lists are valid and expected where no strong read-only source is visible

## Interpretation rules
- Container image OS describes the filesystem inside the container image.
- Visible kernel is an observed signal that usually reflects the host kernel.
- WSL2 kernel fingerprints map to `Virtualization.Kind = WSL2`, `Virtualization.PlatformVendor = Microsoft`, and `UnderlyingHostOs.Family = Windows`.
- `UnderlyingHostOs.Version` remains null for WSL2 because the Windows version is not derivable from the WSL2 kernel.
- Runtime-reported host OS is the highest-confidence host/node view when Docker, Podman, Kubernetes NodeInfo, or cloud metadata is available.
- Hardware is visibility-limited; cgroup limits may differ from physical host capacity.
- Diagnostic fingerprints are correlation helpers only and must not be treated as host identity.
- Identity anchors are modeled separately because some consumers may use them for correlation or license binding, but they remain read-only observed values rather than provisioned platform identities.
- Default safe reports redact sensitive identity-anchor values even though the anchor metadata remains visible.
- Standard Markdown and text reports render a structured `Summary` section first, split into neutral `Environment` facts and scope-oriented `Identity` facts.
- `PlatformEvidence` answers: "What does the observed platform look like?"
- `TrustedPlatforms` answers: "Which explicit local platform claims are strong enough to consume programmatically?"
- For the current Siemens IED flow, `TrustedPlatforms[].VerificationLevel` is monotonic: `1` artifact present, `2` artifact valid and plausible, `3` local endpoint reachable, `4` TLS binding matched.
- For the current Windows TPM flow, `TrustedPlatforms[].VerificationLevel` is intentionally capped at `2`: `1` TPM device present via the local Windows TPM API, `2` TPM device info is plausible. Stronger quote, certificate, or attestation binding is not implemented in this step.
- For the current container TPM visibility flow, `TrustedPlatforms[].VerificationLevel` is intentionally capped at `1`: a TPM-related device node is visible in the current process environment. This is an explicit local artifact, but not a host-identity or ownership proof.
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
  "Summary": {
    "Environment": {
      "Sections": [
        {
          "Kind": "Runtime",
          "Title": "Runtime",
          "Facts": [
            {
              "Label": "Mode",
              "Value": "Containerized",
              "Scope": "Runtime",
              "Level": null,
              "Confidence": "High",
              "SourceKind": "ReportClassification",
              "Usage": "Informational",
              "EvidenceKeys": []
            },
            {
              "Label": "Runtime",
              "Value": "Docker",
              "Scope": "Runtime",
              "Level": null,
              "Confidence": "High",
              "SourceKind": "ReportClassification",
              "Usage": "Informational",
              "EvidenceKeys": []
            }
          ]
        },
        {
          "Kind": "Host",
          "Title": "Host",
          "Facts": [
            {
              "Label": "Host OS",
              "Value": "Ubuntu 24.04.4 LTS",
              "Scope": "Host",
              "Level": null,
              "Confidence": "High",
              "SourceKind": "RuntimeReportedHostOsInfo",
              "Usage": "Informational",
              "EvidenceKeys": ["runtime-api:docker.info.operating_system"]
            },
            {
              "Label": "Hardware",
              "Value": "Microsoft Corporation Virtual Machine",
              "Scope": "Host",
              "Level": null,
              "Confidence": "High",
              "SourceKind": "HostDmiInfo",
              "Usage": "Informational",
              "EvidenceKeys": ["proc-files:dmi.sys_vendor", "proc-files:dmi.product_name"]
            }
          ]
        }
      ]
    },
    "Identity": {
      "Sections": [
        {
          "Kind": "DeploymentIdentity",
          "Title": "Deployment Identity",
          "Facts": [
            {
              "Label": "Deployment Fingerprint",
              "Value": "sha256:...",
              "Scope": "Deployment",
              "Level": 2,
              "Confidence": "Medium",
              "SourceKind": "CRP-HOST-FP-v1",
              "Usage": "Correlation",
              "EvidenceKeys": ["kernel.release"]
            }
          ]
        },
        {
          "Kind": "HostIdentity",
          "Title": "Host Identity",
          "Facts": [
            {
              "Label": "Cloud Host ID",
              "Value": "sha256:...",
              "Scope": "Host",
              "Level": 3,
              "Confidence": "High",
              "SourceKind": "CloudInstanceIdentity",
              "Usage": "BindingCandidate",
              "EvidenceKeys": ["cloud.instance.id"]
            }
          ]
        }
      ]
    }
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
    "DiagnosticFingerprints": [
      {
        "Purpose": "EnvironmentCorrelation",
        "Algorithm": "CRP-HOST-FP-v1",
        "Value": "sha256:...",
        "Stability": "RuntimeApiBacked",
        "StabilityLevel": "UpdateSensitive",
        "UniquenessLevel": "Medium",
        "CorroborationLevel": "CrossSource",
        "SourceClasses": ["KernelSignal", "RuntimeApi"],
        "IncludedSignalCount": 12,
        "ExcludedSensitiveSignalCount": 2,
        "Components": [
          { "Name": "kernel.release", "Included": true, "RawValueRedacted": "6.17.0-1011-azure" }
        ],
        "Warnings": [
          "Fingerprint is diagnostic only and not a security identity."
        ],
        "Reasons": [
          "Includes kernel and runtime signals for environment correlation."
        ]
      }
    ],
    "IdentityAnchors": [
      {
        "Kind": "CloudInstanceIdentity",
        "Algorithm": "CRP-CLOUD-INSTANCE-v1",
        "Value": "sha256:...",
        "Scope": "Host",
        "BindingSuitability": "LicenseBinding",
        "Strength": "Strong",
        "Sensitivity": "Sensitive",
        "EvidenceReferences": ["cloud.instance.id"],
        "Warnings": [],
        "Reasons": [
          "Digest derived from observed cloud instance identity metadata."
        ]
      }
    ]
  }
}
```


## Sample export

`container-runtime-probe sample` emits a dense compact `crp1;...` line, a GitHub issue prefill URL, and optional sample JSON/Markdown output.

Compact samples are ASCII-only, URL-safe, parser-friendly, and redacted by construction. The full sample JSON wrapper adds richer redacted host, hardware, probe outcome, and signal detail for fixtures and regression tests.
