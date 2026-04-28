using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Classification;

internal readonly record struct KernelFlavorSignal(string Signal, KernelFlavor Flavor);

internal static class DetectionMaps
{
    internal static readonly IReadOnlyDictionary<string, OperatingSystemFamily> DistroFamilyById =
        new Dictionary<string, OperatingSystemFamily>(StringComparer.OrdinalIgnoreCase)
        {
            ["ubuntu"] = OperatingSystemFamily.Ubuntu,
            ["ubuntu-core"] = OperatingSystemFamily.Ubuntu,
            ["ubuntu_kylin"] = OperatingSystemFamily.Ubuntu,
            ["debian"] = OperatingSystemFamily.Debian,
            ["linuxmint"] = OperatingSystemFamily.Debian,
            ["pop"] = OperatingSystemFamily.Debian,
            ["elementary"] = OperatingSystemFamily.Debian,
            ["neon"] = OperatingSystemFamily.Debian,
            ["kali"] = OperatingSystemFamily.Debian,
            ["raspbian"] = OperatingSystemFamily.Debian,
            ["alpine"] = OperatingSystemFamily.Alpine,
            ["amzn"] = OperatingSystemFamily.AmazonLinux,
            ["amazon"] = OperatingSystemFamily.AmazonLinux,
            ["azurelinux"] = OperatingSystemFamily.AzureLinux,
            ["mariner"] = OperatingSystemFamily.Mariner,
            ["rhel"] = OperatingSystemFamily.RedHatEnterpriseLinux,
            ["centos"] = OperatingSystemFamily.CentOS,
            ["fedora"] = OperatingSystemFamily.Fedora,
            ["rocky"] = OperatingSystemFamily.RockyLinux,
            ["almalinux"] = OperatingSystemFamily.AlmaLinux,
            ["alma"] = OperatingSystemFamily.AlmaLinux,
            ["opensuse"] = OperatingSystemFamily.OpenSuse,
            ["opensuse-leap"] = OperatingSystemFamily.OpenSuse,
            ["opensuse-tumbleweed"] = OperatingSystemFamily.OpenSuse,
            ["sles"] = OperatingSystemFamily.Suse,
            ["sled"] = OperatingSystemFamily.Suse,
            ["suse"] = OperatingSystemFamily.Suse,
            ["ol"] = OperatingSystemFamily.OracleLinux,
            ["oracle"] = OperatingSystemFamily.OracleLinux,
            ["oraclelinux"] = OperatingSystemFamily.OracleLinux,
            ["wolfi"] = OperatingSystemFamily.Wolfi,
            ["busybox"] = OperatingSystemFamily.BusyBox,
            ["distroless"] = OperatingSystemFamily.Distroless,
            ["photon"] = OperatingSystemFamily.PhotonOS,
            ["flatcar"] = OperatingSystemFamily.Flatcar,
            ["bottlerocket"] = OperatingSystemFamily.Bottlerocket,
            ["rancheros"] = OperatingSystemFamily.RancherOS,
            ["talos"] = OperatingSystemFamily.Talos,
            ["cos"] = OperatingSystemFamily.ContainerOptimizedOS,
            ["container-optimized-os"] = OperatingSystemFamily.ContainerOptimizedOS,
            ["windows"] = OperatingSystemFamily.Windows,
            ["windowsserver"] = OperatingSystemFamily.WindowsServer,
            ["windowsservercore"] = OperatingSystemFamily.WindowsServerCore,
            ["windowsnanoserver"] = OperatingSystemFamily.WindowsNanoServer,
            ["macos"] = OperatingSystemFamily.MacOS,
            ["darwin"] = OperatingSystemFamily.MacOS
        };

    internal static readonly IReadOnlyList<KernelFlavorSignal> KernelFlavorSignals =
    [
        new("microsoft-standard-wsl2", KernelFlavor.WSL2),
        new("wsl2", KernelFlavor.WSL2),
        new("microsoft", KernelFlavor.WSL2),
        new("azure", KernelFlavor.Azure),
        new("aws", KernelFlavor.Aws),
        new("amzn", KernelFlavor.Aws),
        new("gcp", KernelFlavor.Gcp),
        new("google", KernelFlavor.Gcp),
        new("oracle", KernelFlavor.OracleCloud),
        new("synology", KernelFlavor.Synology),
        new("qnap", KernelFlavor.Qnap),
        new("ubuntu", KernelFlavor.Ubuntu),
        new("debian", KernelFlavor.Debian),
        new("docker desktop", KernelFlavor.DockerDesktop),
        new("linuxkit", KernelFlavor.DockerDesktop),
        new("buildroot", KernelFlavor.Embedded),
        new("yocto", KernelFlavor.Embedded),
        new("openwrt", KernelFlavor.Embedded),
        new("raspberry", KernelFlavor.RaspberryPi),
        new("raspi", KernelFlavor.RaspberryPi),
        new("lowlatency", KernelFlavor.LowLatency),
        new("realtime", KernelFlavor.Realtime)
    ];

    internal static readonly IReadOnlyList<string> CustomCompilerSignals =
    [
        "crosstool",
        "buildroot",
        "uclibc",
        "musl",
        "synology",
        "qnap"
    ];

    internal static readonly IReadOnlyList<string> VendorApplianceSignals =
    [
        "synology",
        "qnap",
        "qts",
        "quts",
        "dsm",
        "diskstation",
        "ubios"
    ];

    internal static readonly IReadOnlyList<string> HomeDnsSignals =
    [
        "lan",
        ".lan",
        ".home",
        ".local",
        "fritz.box"
    ];
}