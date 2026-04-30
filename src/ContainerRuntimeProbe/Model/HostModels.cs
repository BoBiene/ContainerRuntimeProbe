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
    VirtualizationInfo Virtualization,
    UnderlyingHostOsInfo UnderlyingHostOs,
    HostHardwareInfo Hardware,
    HostFingerprint? Fingerprint);

#pragma warning restore CS1591
