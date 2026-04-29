using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Classification;

internal readonly record struct KernelFlavorSignal(string Signal, KernelFlavor Flavor);

internal static class DetectionMaps
{
    internal static readonly IReadOnlyDictionary<string, OperatingSystemFamily> DistroFamilyById =
        new Dictionary<string, OperatingSystemFamily>(StringComparer.OrdinalIgnoreCase)
        {
            // Ubuntu
            ["ubuntu"] = OperatingSystemFamily.Ubuntu,
            ["ubuntu-core"] = OperatingSystemFamily.Ubuntu,
            ["ubuntu_kylin"] = OperatingSystemFamily.Ubuntu,
            ["zorin"] = OperatingSystemFamily.Ubuntu,
            ["pika"] = OperatingSystemFamily.Ubuntu,
            ["trisquel"] = OperatingSystemFamily.Ubuntu,
            ["bodhi"] = OperatingSystemFamily.Ubuntu,
            ["vanillaos"] = OperatingSystemFamily.Ubuntu,
            // Debian
            ["debian"] = OperatingSystemFamily.Debian,
            ["linuxmint"] = OperatingSystemFamily.Debian,
            ["pop"] = OperatingSystemFamily.Debian,
            ["elementary"] = OperatingSystemFamily.Debian,
            ["neon"] = OperatingSystemFamily.Debian,
            ["kali"] = OperatingSystemFamily.Debian,
            ["raspbian"] = OperatingSystemFamily.Debian,
            ["devuan"] = OperatingSystemFamily.Debian,
            ["parrot"] = OperatingSystemFamily.Debian,
            ["pureos"] = OperatingSystemFamily.Debian,
            ["tails"] = OperatingSystemFamily.Debian,
            // Alpine
            ["alpine"] = OperatingSystemFamily.Alpine,
            // Arch
            ["arch"] = OperatingSystemFamily.Arch,
            ["manjaro"] = OperatingSystemFamily.Arch,
            ["steamos"] = OperatingSystemFamily.Arch,
            ["endeavouros"] = OperatingSystemFamily.Arch,
            ["garuda"] = OperatingSystemFamily.Arch,
            ["rebornos"] = OperatingSystemFamily.Arch,
            ["cachyos"] = OperatingSystemFamily.Arch,
            ["blackarch"] = OperatingSystemFamily.Arch,
            // Amazon Linux
            ["amzn"] = OperatingSystemFamily.AmazonLinux,
            ["amazon"] = OperatingSystemFamily.AmazonLinux,
            // Azure Linux / Mariner
            ["azurelinux"] = OperatingSystemFamily.AzureLinux,
            ["mariner"] = OperatingSystemFamily.Mariner,
            // OpenWrt
            ["openwrt"] = OperatingSystemFamily.OpenWrt,
            // RHEL family
            ["rhel"] = OperatingSystemFamily.RedHatEnterpriseLinux,
            ["eurolinux"] = OperatingSystemFamily.RedHatEnterpriseLinux,
            ["miraclelinux"] = OperatingSystemFamily.RedHatEnterpriseLinux,
            ["scientific"] = OperatingSystemFamily.RedHatEnterpriseLinux,
            ["tencentos"] = OperatingSystemFamily.RedHatEnterpriseLinux,
            ["clearos"] = OperatingSystemFamily.RedHatEnterpriseLinux,
            ["xcpng"] = OperatingSystemFamily.RedHatEnterpriseLinux,
            ["xcp-ng"] = OperatingSystemFamily.RedHatEnterpriseLinux,
            ["xenenterprise"] = OperatingSystemFamily.RedHatEnterpriseLinux,
            // CentOS
            ["centos"] = OperatingSystemFamily.CentOS,
            // Fedora (including Universal Blue immutable variants)
            ["fedora"] = OperatingSystemFamily.Fedora,
            ["fedoraremixforwsl"] = OperatingSystemFamily.Fedora,
            ["bluefin"] = OperatingSystemFamily.Fedora,
            ["aurora"] = OperatingSystemFamily.Fedora,
            ["bazzite"] = OperatingSystemFamily.Fedora,
            ["nobara"] = OperatingSystemFamily.Fedora,
            ["ultramarine"] = OperatingSystemFamily.Fedora,
            // Rocky / Alma
            ["rocky"] = OperatingSystemFamily.RockyLinux,
            ["almalinux"] = OperatingSystemFamily.AlmaLinux,
            ["alma"] = OperatingSystemFamily.AlmaLinux,
            // SUSE / openSUSE
            ["opensuse"] = OperatingSystemFamily.OpenSuse,
            ["opensuse-leap"] = OperatingSystemFamily.OpenSuse,
            ["opensuse-tumbleweed"] = OperatingSystemFamily.OpenSuse,
            ["suse-microos"] = OperatingSystemFamily.OpenSuse,
            ["sles"] = OperatingSystemFamily.Suse,
            ["sled"] = OperatingSystemFamily.Suse,
            ["suse"] = OperatingSystemFamily.Suse,
            // Oracle Linux
            ["ol"] = OperatingSystemFamily.OracleLinux,
            ["oracle"] = OperatingSystemFamily.OracleLinux,
            ["oraclelinux"] = OperatingSystemFamily.OracleLinux,
            // Container-optimized / immutable
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
            ["coreos"] = OperatingSystemFamily.CoreOS,
            // Independent / unique families
            ["nixos"] = OperatingSystemFamily.NixOS,
            ["void"] = OperatingSystemFamily.VoidLinux,
            ["gentoo"] = OperatingSystemFamily.Gentoo,
            ["openeuler"] = OperatingSystemFamily.OpenEuler,
            ["clear-linux-os"] = OperatingSystemFamily.ClearLinux,
            // Embedded
            ["buildroot"] = OperatingSystemFamily.Embedded,
            // Windows
            ["windows"] = OperatingSystemFamily.Windows,
            ["windowsserver"] = OperatingSystemFamily.WindowsServer,
            ["windowsservercore"] = OperatingSystemFamily.WindowsServerCore,
            ["windowsnanoserver"] = OperatingSystemFamily.WindowsNanoServer,
            // macOS
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