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
    LowLatency
}

/// <summary>Trusted source for runtime-reported host OS information.</summary>
public enum RuntimeReportedHostSource
{
    Unknown,
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

/// <summary>Normalized visible kernel details observed from inside the container.</summary>
public sealed record VisibleKernelInfo(
    string? Name,
    string? Release,
    string? Version,
    ArchitectureKind Architecture,
    string? RawArchitecture,
    KernelFlavor Flavor,
    string? Compiler,
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

/// <summary>Normalized visible hardware summary.</summary>
public sealed record HostHardwareInfo(
    ArchitectureKind Architecture,
    string? RawArchitecture,
    HostCpuInfo Cpu,
    HostMemoryInfo Memory,
    string? CloudMachineType);

/// <summary>Single host fingerprint component.</summary>
public sealed record HostFingerprintComponent(
    string Name,
    bool Included,
    string RawValueRedacted);

/// <summary>Privacy-aware host fingerprint for correlation and diagnostics.</summary>
public sealed record HostFingerprint(
    string Algorithm,
    string Value,
    FingerprintStability Stability,
    int IncludedSignalCount,
    int ExcludedSensitiveSignalCount,
    IReadOnlyList<HostFingerprintComponent> Components,
    IReadOnlyList<string> Warnings);

/// <summary>Structured host report attached to the container runtime report.</summary>
public sealed record HostReport(
    ContainerImageOsInfo ContainerImageOs,
    VisibleKernelInfo VisibleKernel,
    RuntimeReportedHostOsInfo RuntimeReportedHostOs,
    HostHardwareInfo Hardware,
    HostFingerprint? Fingerprint);

#pragma warning restore CS1591
