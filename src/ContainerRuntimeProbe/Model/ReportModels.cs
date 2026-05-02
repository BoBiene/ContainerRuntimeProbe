using System.Text.Json.Serialization;
using ContainerRuntimeProbe.Abstractions;

namespace ContainerRuntimeProbe.Model;

/// <summary>An observed evidence key/value emitted by a probe.</summary>
public sealed record EvidenceItem(string ProbeId, string Key, string? Value, EvidenceSensitivity Sensitivity = EvidenceSensitivity.Public);

/// <summary>A probe execution result with normalized outcome and evidence payload.</summary>
public sealed record ProbeResult(string ProbeId, ProbeOutcome Outcome, IReadOnlyList<EvidenceItem> Evidence, string? Message = null, TimeSpan? Duration = null);

/// <summary>Security warning surfaced at report level.</summary>
public sealed record SecurityWarning(string Code, string Message);

/// <summary>Probe tool version and source control information.</summary>
public sealed record ProbeToolMetadata(string Version, string? GitCommit);

/// <summary>Reason object including evidence references used for an inferred classification.</summary>
public sealed record ClassificationReason(string Message, IReadOnlyList<string> EvidenceKeys);

/// <summary>Classifies the strength of heuristic platform evidence.</summary>
public enum PlatformEvidenceLevel
{
    /// <summary>No platform evidence is available.</summary>
    None,

    /// <summary>Only weak hints are available.</summary>
    WeakHint,

    /// <summary>Evidence is strong enough for a heuristic platform conclusion.</summary>
    Heuristic,

    /// <summary>Evidence is strongly corroborated by multiple sources.</summary>
    StrongHeuristic
}

/// <summary>Represents the trust state of an explicit platform claim.</summary>
public enum TrustedPlatformState
{
    /// <summary>No explicit trusted platform claim is available.</summary>
    None,

    /// <summary>An explicit platform claim exists but is not locally verified.</summary>
    Claimed,

    /// <summary>An explicit platform claim is locally verified.</summary>
    Verified,

    /// <summary>An explicit platform claim is backed by stronger attestation.</summary>
    Attested
}

/// <summary>Identifies a generic platform evidence item category.</summary>
public enum PlatformEvidenceType
{
    /// <summary>Generic platform signal.</summary>
    Signal,

    /// <summary>Hardware or firmware corroboration.</summary>
    Hardware,

    /// <summary>Runtime metadata corroboration.</summary>
    RuntimeMetadata,

    /// <summary>Hostname or DNS context hint.</summary>
    NetworkContext,

    /// <summary>Environment variable hint.</summary>
    Environment,

    /// <summary>Mount or cgroup context hint.</summary>
    ExecutionContext,

    /// <summary>Trust-related artifact reference.</summary>
    TrustArtifact
}

/// <summary>Identifies the origin of a trusted platform claim.</summary>
public enum TrustedPlatformSourceType
{
    /// <summary>The source type is not known.</summary>
    Unknown,

    /// <summary>The claim originates from a local mounted file.</summary>
    LocalFile,

    /// <summary>The claim originates from a local device node visible to the current process.</summary>
    LocalDeviceNode,

    /// <summary>The claim originates from local runtime metadata.</summary>
    RuntimeMetadata,

    /// <summary>The claim originates from a local hardware-backed platform API.</summary>
    LocalHardwareApi,

    /// <summary>The claim originates from a local endpoint validation flow.</summary>
    LocalEndpoint,

    /// <summary>The claim originates from local TLS or certificate verification.</summary>
    TlsBinding
}

/// <summary>Identifies the scope of a trusted platform claim.</summary>
public enum TrustedPlatformClaimScope
{
    /// <summary>Generic platform presence or identity.</summary>
    PlatformPresence,

    /// <summary>Runtime or device presence.</summary>
    RuntimePresence,

    /// <summary>Management plane presence.</summary>
    ManagementPlane
}

/// <summary>Represents a normalized heuristic platform evidence item.</summary>
public sealed record PlatformEvidenceItem(
    PlatformEvidenceType Type,
    string Key,
    string? Value,
    Confidence Confidence,
    string Description);

/// <summary>Represents a summarized heuristic platform hypothesis.</summary>
public sealed record PlatformEvidenceSummary(
    string PlatformKey,
    int Score,
    PlatformEvidenceLevel EvidenceLevel,
    Confidence Confidence,
    IReadOnlyList<PlatformEvidenceItem> Evidence,
    IReadOnlyList<string> Warnings);

/// <summary>Represents a trusted platform claim exposed to applications.</summary>
public sealed record TrustedPlatformClaim(
    TrustedPlatformClaimScope Scope,
    string Type,
    string? Value,
    Confidence Confidence,
    string Description);

/// <summary>Represents explicit evidence used for a trusted platform claim.</summary>
public sealed record TrustedPlatformEvidence(
    TrustedPlatformSourceType SourceType,
    string Key,
    string? Value,
    Confidence Confidence,
    string Description);

/// <summary>Represents a summarized trusted platform entry.</summary>
public sealed record TrustedPlatformSummary(
    string PlatformKey,
    TrustedPlatformState State,
    string? VerificationMethod,
    string? Issuer,
    string? Subject,
    DateTimeOffset? ExpiresAt,
    IReadOnlyList<TrustedPlatformClaim> Claims,
    IReadOnlyList<TrustedPlatformEvidence> Evidence,
    IReadOnlyList<string> Warnings)
{
    /// <summary>Monotonic local verification level for the trusted platform entry.</summary>
    public int VerificationLevel { get; init; }
}

/// <summary>Classifies whether the current process appears to run in a container.</summary>
public enum ContainerizationKind
{
    /// <summary>The available evidence is not sufficient for a determination.</summary>
    Unknown,

    /// <summary>Evidence indicates the current process is not containerized.</summary>
    @False,

    /// <summary>Evidence indicates the current process is containerized.</summary>
    @True
}

/// <summary>Classifies the detected container runtime implementation.</summary>
public enum ContainerRuntimeKind
{
    /// <summary>No runtime could be inferred.</summary>
    Unknown,

    /// <summary>Docker Engine runtime.</summary>
    Docker,

    /// <summary>Podman runtime.</summary>
    Podman,

    /// <summary>containerd runtime.</summary>
    Containerd,

    /// <summary>CRI-O runtime.</summary>
    CriO
}

/// <summary>Classifies the visible virtualization environment.</summary>
public enum VirtualizationClassificationKind
{
    /// <summary>No reliable virtualization signal is available.</summary>
    Unknown,

    /// <summary>No virtualization fingerprint was detected.</summary>
    None,

    /// <summary>Generic hypervisor or VM signals were detected, but provider attribution is not explicit yet.</summary>
    VirtualMachine,

    /// <summary>Hyper-V guest signals were detected.</summary>
    HyperV,

    /// <summary>VMware guest signals were detected.</summary>
    VMware,

    /// <summary>Oracle VirtualBox guest signals were detected.</summary>
    VirtualBox,

    /// <summary>Xen guest signals were detected.</summary>
    Xen,

    /// <summary>KVM or QEMU guest signals were detected.</summary>
    Kvm,

    /// <summary>The kernel fingerprint matches WSL2.</summary>
    WSL2
}

/// <summary>Classifies the broader host type derived from host signals.</summary>
public enum HostTypeKind
{
    /// <summary>The host type could not be inferred.</summary>
    Unknown,

    /// <summary>A conventional Linux host without appliance mismatch signals.</summary>
    StandardLinux,

    /// <summary>A vendor appliance or similarly specialized Linux host.</summary>
    Appliance,

    /// <summary>A Windows host surfaced through WSL2.</summary>
    WSL2
}

/// <summary>Classifies the broader hosting environment.</summary>
public enum EnvironmentTypeKind
{
    /// <summary>The environment could not be inferred.</summary>
    Unknown,

    /// <summary>The host appears to run in a cloud environment.</summary>
    Cloud,

    /// <summary>The host appears to run outside managed cloud infrastructure.</summary>
    OnPrem
}

/// <summary>Classifies the API surface exposed by a detected runtime.</summary>
public enum RuntimeApiKind
{
    /// <summary>No runtime API could be inferred.</summary>
    Unknown,

    /// <summary>Docker Engine API.</summary>
    DockerEngineApi,

    /// <summary>Podman Libpod API.</summary>
    PodmanLibpodApi,

    /// <summary>Kubernetes API.</summary>
    KubernetesApi
}

/// <summary>Classifies the detected container orchestrator.</summary>
public enum OrchestratorKind
{
    /// <summary>No orchestrator could be inferred.</summary>
    Unknown,

    /// <summary>Kubernetes or a compatible control plane.</summary>
    Kubernetes,

    /// <summary>AWS ECS.</summary>
    AwsEcs,

    /// <summary>Google Cloud Run.</summary>
    CloudRun,

    /// <summary>Azure Container Apps.</summary>
    AzureContainerApps,

    /// <summary>HashiCorp Nomad.</summary>
    Nomad,

    /// <summary>OpenShift.</summary>
    OpenShift,

    /// <summary>Docker Compose.</summary>
    DockerCompose
}

/// <summary>Classifies the detected cloud provider.</summary>
public enum CloudProviderKind
{
    /// <summary>No cloud provider could be inferred.</summary>
    Unknown,

    /// <summary>Amazon Web Services.</summary>
    AWS,

    /// <summary>Microsoft Azure.</summary>
    Azure,

    /// <summary>Google Cloud Platform.</summary>
    GoogleCloud,

    /// <summary>Oracle Cloud Infrastructure.</summary>
    OracleCloud
}

/// <summary>Classifies a higher-level platform vendor or appliance family.</summary>
public enum PlatformVendorKind
{
    /// <summary>No platform vendor could be inferred.</summary>
    Unknown,

    /// <summary>Microsoft platform signals, typically WSL2.</summary>
    Microsoft,

    /// <summary>Synology platform signals.</summary>
    Synology,

    /// <summary>Apple platform signals, typically Docker Desktop on macOS.</summary>
    Apple,

    /// <summary>Siemens hardware platform signals.</summary>
    Siemens,

    /// <summary>Siemens Industrial Edge signals.</summary>
    SiemensIndustrialEdge,

    /// <summary>WAGO hardware platform signals.</summary>
    Wago,

    /// <summary>Beckhoff hardware platform signals.</summary>
    Beckhoff,

    /// <summary>Phoenix Contact hardware platform signals.</summary>
    PhoenixContact,

    /// <summary>Advantech hardware platform signals.</summary>
    Advantech,

    /// <summary>Moxa hardware platform signals.</summary>
    Moxa,

    /// <summary>Bosch Rexroth hardware platform signals.</summary>
    BoschRexroth,

    /// <summary>Schneider Electric hardware platform signals.</summary>
    SchneiderElectric,

    /// <summary>B&amp;R hardware platform signals.</summary>
    BAndR,

    /// <summary>Opto 22 groov EPIC and related hardware platform signals.</summary>
    Opto22,

    /// <summary>Stratus ztC Edge and related hardware platform signals.</summary>
    Stratus,

    /// <summary>Azure IoT Edge signals without Siemens-specific corroboration.</summary>
    IoTEdge
}

/// <summary>Single classification value with confidence and justification.</summary>
public sealed record ClassificationResult<TValue>(TValue Value, Confidence Confidence, IReadOnlyList<ClassificationReason> Reasons)
    where TValue : struct, Enum;

/// <summary>Structured host classification dimension.</summary>
public sealed record HostClassificationResult(
    ClassificationResult<OperatingSystemFamily> Family,
    ClassificationResult<HostTypeKind> Type);

/// <summary>Structured environment classification dimension.</summary>
public sealed record EnvironmentClassificationResult(
    ClassificationResult<EnvironmentTypeKind> Type);

/// <summary>Container runtime report classification dimensions.</summary>
public sealed record ReportClassification(
    ClassificationResult<ContainerizationKind> IsContainerized,
    ClassificationResult<ContainerRuntimeKind> ContainerRuntime,
    ClassificationResult<VirtualizationClassificationKind> Virtualization,
    HostClassificationResult Host,
    EnvironmentClassificationResult Environment,
    ClassificationResult<RuntimeApiKind> RuntimeApi,
    ClassificationResult<OrchestratorKind> Orchestrator,
    ClassificationResult<CloudProviderKind> CloudProvider,
    ClassificationResult<PlatformVendorKind> PlatformVendor);

/// <summary>Top-level report returned by the probe engine.</summary>
public sealed record ContainerRuntimeReport(
    DateTimeOffset GeneratedAt,
    TimeSpan Duration,
    ProbeToolMetadata? ProbeToolInfo,
    IReadOnlyList<ProbeResult> Probes,
    IReadOnlyList<SecurityWarning> SecurityWarnings,
    ReportClassification Classification,
    HostReport Host,
    IReadOnlyList<PlatformEvidenceSummary>? PlatformEvidence = null,
    IReadOnlyList<TrustedPlatformSummary>? TrustedPlatforms = null,
    ReportSummary? Summary = null);

/// <summary>Source-generation context for JSON serialization.</summary>
[JsonSerializable(typeof(ContainerRuntimeReport))]
[JsonSerializable(typeof(ReportSummary))]
[JsonSerializable(typeof(EnvironmentSummary))]
[JsonSerializable(typeof(IdentitySummary))]
[JsonSerializable(typeof(EnvironmentSummarySection))]
[JsonSerializable(typeof(IdentitySummarySection))]
[JsonSerializable(typeof(SummaryFact))]
[JsonSerializable(typeof(SummaryScope))]
[JsonSerializable(typeof(SummaryUsageKind))]
[JsonSerializable(typeof(EnvironmentSummarySectionKind))]
[JsonSerializable(typeof(IdentitySummarySectionKind))]
[JsonSerializable(typeof(SummaryVariantKind))]
[JsonSerializable(typeof(ClassificationResult<ContainerizationKind>))]
[JsonSerializable(typeof(ClassificationResult<ContainerRuntimeKind>))]
[JsonSerializable(typeof(ClassificationResult<VirtualizationClassificationKind>))]
[JsonSerializable(typeof(ClassificationResult<OperatingSystemFamily>))]
[JsonSerializable(typeof(ClassificationResult<HostTypeKind>))]
[JsonSerializable(typeof(ClassificationResult<EnvironmentTypeKind>))]
[JsonSerializable(typeof(ClassificationResult<RuntimeApiKind>))]
[JsonSerializable(typeof(ClassificationResult<OrchestratorKind>))]
[JsonSerializable(typeof(ClassificationResult<CloudProviderKind>))]
[JsonSerializable(typeof(ClassificationResult<PlatformVendorKind>))]
[JsonSerializable(typeof(PlatformEvidenceSummary))]
[JsonSerializable(typeof(PlatformEvidenceItem))]
[JsonSerializable(typeof(TrustedPlatformSummary))]
[JsonSerializable(typeof(TrustedPlatformClaim))]
[JsonSerializable(typeof(TrustedPlatformEvidence))]
[JsonSerializable(typeof(PlatformEvidenceLevel))]
[JsonSerializable(typeof(TrustedPlatformState))]
[JsonSerializable(typeof(PlatformEvidenceType))]
[JsonSerializable(typeof(TrustedPlatformSourceType))]
[JsonSerializable(typeof(TrustedPlatformClaimScope))]
[JsonSerializable(typeof(List<PlatformEvidenceSummary>))]
[JsonSerializable(typeof(List<TrustedPlatformSummary>))]
[JsonSerializable(typeof(List<EnvironmentSummarySection>))]
[JsonSerializable(typeof(List<IdentitySummarySection>))]
[JsonSerializable(typeof(List<SummaryFact>))]
[JsonSerializable(typeof(string[]))]
[JsonSourceGenerationOptions(WriteIndented = true, UseStringEnumConverter = true)]
public partial class ReportJsonContext : JsonSerializerContext;
