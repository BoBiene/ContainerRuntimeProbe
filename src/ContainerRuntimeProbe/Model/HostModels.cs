using System.Text.Json.Serialization;
using ContainerRuntimeProbe.Abstractions;

namespace ContainerRuntimeProbe.Model;

#pragma warning disable CS1591

/// <summary>Normalized operating system family or distribution.</summary>
public enum OperatingSystemFamily
{
    Unknown,
    Linux,
    Windows,
    MacOS,
    Debian,
    Ubuntu,
    Alpine,
    Arch,
    OpenWrt,
    RedHatEnterpriseLinux,
    CentOS,
    Fedora,
    RockyLinux,
    AlmaLinux,
    AmazonLinux,
    AzureLinux,
    Mariner,
    Suse,
    OpenSuse,
    OracleLinux,
    Wolfi,
    BusyBox,
    Distroless,
    PhotonOS,
    Flatcar,
    Bottlerocket,
    RancherOS,
    Talos,
    ContainerOptimizedOS,
    CoreOS,
    NixOS,
    VoidLinux,
    Gentoo,
    OpenEuler,
    ClearLinux,
    Embedded,
    WindowsServer,
    WindowsNanoServer,
    WindowsServerCore
}

/// <summary>Normalized CPU architecture.</summary>
public enum ArchitectureKind
{
    Unknown,
    X86,
    X64,
    Arm,
    Arm64,
    S390x,
    Ppc64le,
    RiscV64,
    Wasm
}

/// <summary>Normalized kernel flavor hints.</summary>
public enum KernelFlavor
{
    Unknown,
    Generic,
    Azure,
    Aws,
    Gcp,
    OracleCloud,
    WSL2,
    DockerDesktop,
    RaspberryPi,
    Realtime,
    LowLatency,
    Embedded,
    Qnap,
    Synology,
    Ubuntu,
    Debian
}

/// <summary>Normalized virtualization environment derived from kernel or platform signals.</summary>
public enum VirtualizationKind
{
    Unknown,
    VirtualMachine,
    WSL2,
    HyperV,
    VMware,
    VirtualBox,
    Xen,
    Kvm
}

/// <summary>Heuristic source for inferred underlying host OS information.</summary>
public enum UnderlyingHostOsSource
{
    Unknown,
    VisibleKernel,
    Virtualization
}

/// <summary>Trusted source for runtime-reported host OS information.</summary>
public enum RuntimeReportedHostSource
{
    Unknown,
    LocalHost,
    DockerInfo,
    PodmanInfo,
    KubernetesNodeInfo,
    AzureImds,
    AwsMetadata,
    GcpMetadata,
    OciMetadata
}

/// <summary>Host fingerprint collection mode.</summary>
public enum FingerprintMode
{
    None,
    Safe,
    Extended
}

/// <summary>Expected stability class of the generated host fingerprint.</summary>
public enum FingerprintStability
{
    Unknown,
    BestEffort,
    RuntimeApiBacked,
    CloudMetadataBacked,
    KernelOnly,
    ContainerOnly
}

/// <summary>Intended purpose of a diagnostic fingerprint.</summary>
public enum DiagnosticFingerprintPurpose
{
    EnvironmentCorrelation,
    HostProfile,
    RuntimeProfile
}

/// <summary>Expected update tolerance of a diagnostic fingerprint.</summary>
public enum DiagnosticFingerprintStabilityLevel
{
    Ephemeral,
    UpdateSensitive,
    ProfileStable,
    PlatformAnchored
}

/// <summary>Expected distinctiveness of a diagnostic fingerprint.</summary>
public enum DiagnosticFingerprintUniquenessLevel
{
    Unknown,
    Low,
    Medium,
    High
}

/// <summary>How broadly a diagnostic fingerprint is corroborated by independent sources.</summary>
public enum DiagnosticFingerprintCorroborationLevel
{
    Unknown,
    SingleSource,
    CrossSource,
    TrustedPlatformCorroborated
}

/// <summary>Normalized source class contributing to a diagnostic fingerprint.</summary>
public enum DiagnosticFingerprintSourceClass
{
    Unknown,
    KernelSignal,
    RuntimeApi,
    CloudMetadata,
    HardwareProfile,
    KubernetesMetadata
}

/// <summary>Observed identity anchor kind.</summary>
public enum IdentityAnchorKind
{
    Unknown,
    TpmPublicKeyDigest,
    MachineCertificateDigest,
    MachineIdDigest,
    CloudInstanceIdentity,
    KubernetesNodeIdentity,
    VendorRuntimeIdentity,
    ContainerDeviceAnchor
}

/// <summary>Scope described by an identity anchor.</summary>
public enum IdentityAnchorScope
{
    Unknown,
    Host,
    Platform,
    ContainerRuntime,
    Workload,
    ApplicationHost
}

/// <summary>Supported usage class for an identity anchor.</summary>
public enum BindingSuitability
{
    DiagnosticsOnly,
    Correlation,
    LicenseBinding,
    ExternalAttestation
}

/// <summary>Relative strength of an identity anchor.</summary>
public enum IdentityAnchorStrength
{
    Unknown,
    Weak,
    Medium,
    Strong
}

/// <summary>Sensitivity classification for identity anchor values.</summary>
public enum IdentityAnchorSensitivity
{
    Public,
    Sensitive
}

/// <summary>Normalized container image OS details.</summary>
public sealed record ContainerImageOsInfo(
    OperatingSystemFamily Family,
    string? Id,
    IReadOnlyList<string> IdLike,
    string? Name,
    string? PrettyName,
    string? Version,
    string? VersionId,
    string? VersionCodename,
    string? BuildId,
    string? Variant,
    string? VariantId,
    string? HomeUrl,
    string? SupportUrl,
    string? BugReportUrl,
    ArchitectureKind Architecture,
    string? RawArchitecture,
    Confidence Confidence,
    IReadOnlyList<string> EvidenceReferences);

/// <summary>Structured compiler metadata extracted from the visible kernel build string.</summary>
[JsonConverter(typeof(KernelCompilerInfoJsonConverter))]
public sealed record KernelCompilerInfo(
    string? Name,
    string? Version,
    string? Raw,
    string? DistributionHint,
    string? DistributionVersionHint);

/// <summary>Normalized visible kernel details observed from inside the container.</summary>
public sealed record VisibleKernelInfo(
    string? Name,
    string? Release,
    string? Version,
    ArchitectureKind Architecture,
    string? RawArchitecture,
    KernelFlavor Flavor,
    KernelCompilerInfo? Compiler,
    Confidence Confidence,
    IReadOnlyList<string> EvidenceReferences);

/// <summary>Trusted runtime or platform metadata describing the host OS.</summary>
public sealed record RuntimeReportedHostOsInfo(
    OperatingSystemFamily Family,
    string? Name,
    string? Version,
    string? KernelVersion,
    ArchitectureKind Architecture,
    string? RawArchitecture,
    RuntimeReportedHostSource Source,
    Confidence Confidence,
    IReadOnlyList<string> EvidenceReferences);

/// <summary>Normalized virtualization details derived from local host signals.</summary>
public sealed record VirtualizationInfo(
    VirtualizationKind Kind,
    string? PlatformVendor,
    Confidence Confidence,
    IReadOnlyList<string> EvidenceReferences);

/// <summary>Best-effort underlying host OS inferred from virtualization context.</summary>
public sealed record UnderlyingHostOsInfo(
    OperatingSystemFamily Family,
    string? Name,
    string? Version,
    string? VersionHint,
    UnderlyingHostOsSource Source,
    Confidence Confidence,
    IReadOnlyList<string> EvidenceReferences);

/// <summary>Normalized visible CPU details.</summary>
public sealed record HostCpuInfo(
    int? LogicalProcessorCount,
    int? VisibleProcessorCount,
    string? Vendor,
    string? ModelName,
    string? Family,
    string? FlagsHash,
    int? FlagsCount,
    long? CgroupCpuQuota,
    string? CgroupCpuMax);

/// <summary>Normalized visible memory details.</summary>
public sealed record HostMemoryInfo(
    long? MemTotalBytes,
    long? CgroupMemoryLimitBytes,
    long? CgroupMemoryCurrentBytes,
    string? CgroupMemoryLimitRaw);

/// <summary>Normalized public DMI / firmware platform details.</summary>
public sealed record HostDmiInfo(
    string? SystemVendor,
    string? ProductName,
    string? ProductFamily,
    string? ProductVersion,
    string? BoardVendor,
    string? BoardName,
    string? ChassisVendor,
    string? BiosVendor,
    string? Modalias,
    Confidence Confidence,
    IReadOnlyList<string> EvidenceReferences);

/// <summary>Normalized public device-tree platform details.</summary>
public sealed record HostDeviceTreeInfo(
    string? Model,
    string? Compatible,
    Confidence Confidence,
    IReadOnlyList<string> EvidenceReferences);

/// <summary>Normalized visible hardware summary.</summary>
public sealed record HostHardwareInfo(
    ArchitectureKind Architecture,
    string? RawArchitecture,
    HostCpuInfo Cpu,
    HostMemoryInfo Memory,
    HostDmiInfo Dmi,
    HostDeviceTreeInfo DeviceTree,
    string? CloudMachineType);

/// <summary>Single diagnostic fingerprint component.</summary>
public sealed record DiagnosticFingerprintComponent(
    string Name,
    bool Included,
    string RawValueRedacted);

/// <summary>Privacy-aware diagnostic fingerprint for correlation and profiling.</summary>
public sealed record DiagnosticFingerprint(
    DiagnosticFingerprintPurpose Purpose,
    string Algorithm,
    string Value,
    FingerprintStability Stability,
    DiagnosticFingerprintStabilityLevel StabilityLevel,
    DiagnosticFingerprintUniquenessLevel UniquenessLevel,
    DiagnosticFingerprintCorroborationLevel CorroborationLevel,
    int IncludedSignalCount,
    int ExcludedSensitiveSignalCount,
    IReadOnlyList<DiagnosticFingerprintSourceClass> SourceClasses,
    IReadOnlyList<DiagnosticFingerprintComponent> Components,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Reasons);

/// <summary>Observed identity anchor suitable for correlation or binding scenarios.</summary>
public sealed record IdentityAnchor(
    IdentityAnchorKind Kind,
    string Algorithm,
    string Value,
    IdentityAnchorScope Scope,
    BindingSuitability BindingSuitability,
    IdentityAnchorStrength Strength,
    IdentityAnchorSensitivity Sensitivity,
    IReadOnlyList<string> EvidenceReferences,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Reasons);

/// <summary>Structured host report attached to the container runtime report.</summary>
public sealed record HostReport(
    ContainerImageOsInfo ContainerImageOs,
    VisibleKernelInfo VisibleKernel,
    RuntimeReportedHostOsInfo RuntimeReportedHostOs,
    VirtualizationInfo Virtualization,
    UnderlyingHostOsInfo UnderlyingHostOs,
    HostHardwareInfo Hardware,
    IReadOnlyList<DiagnosticFingerprint> DiagnosticFingerprints,
    IReadOnlyList<IdentityAnchor> IdentityAnchors);

#pragma warning restore CS1591
