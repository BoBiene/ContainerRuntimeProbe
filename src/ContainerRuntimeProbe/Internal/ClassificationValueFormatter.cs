using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Internal;

internal static class ClassificationValueFormatter
{
    public static string Format(ContainerizationKind value)
        => value switch
        {
            ContainerizationKind.@True => "True",
            ContainerizationKind.@False => "False",
            _ => KnownValues.Unknown
        };

    public static string Format(ContainerRuntimeKind value)
        => value switch
        {
            ContainerRuntimeKind.Containerd => "containerd",
            ContainerRuntimeKind.CriO => "CRI-O",
            ContainerRuntimeKind.Unknown => KnownValues.Unknown,
            _ => value.ToString()
        };

    public static string Format(VirtualizationClassificationKind value)
        => value switch
        {
            VirtualizationClassificationKind.VirtualMachine => "Virtual Machine",
            VirtualizationClassificationKind.HyperV => "Hyper-V",
            VirtualizationClassificationKind.VMware => "VMware",
            VirtualizationClassificationKind.VirtualBox => "VirtualBox",
            VirtualizationClassificationKind.Xen => "Xen",
            VirtualizationClassificationKind.Kvm => "KVM/QEMU",
            VirtualizationClassificationKind.WSL2 => "WSL2",
            VirtualizationClassificationKind.None => "None",
            _ => KnownValues.Unknown
        };

    public static string Format(HostTypeKind value)
        => value switch
        {
            HostTypeKind.WSL2 => "WSL2",
            HostTypeKind.Unknown => KnownValues.Unknown,
            _ => value.ToString()
        };

    public static string Format(EnvironmentTypeKind value)
        => value == EnvironmentTypeKind.Unknown ? KnownValues.Unknown : value.ToString();

    public static string Format(RuntimeApiKind value)
        => value == RuntimeApiKind.Unknown ? KnownValues.Unknown : value.ToString();

    public static string Format(OrchestratorKind value)
        => value switch
        {
            OrchestratorKind.AwsEcs => "AWS ECS",
            OrchestratorKind.CloudRun => "Cloud Run",
            OrchestratorKind.AzureContainerApps => "Azure Container Apps",
            OrchestratorKind.Unknown => KnownValues.Unknown,
            _ => value.ToString()
        };

    public static string Format(CloudProviderKind value)
        => value == CloudProviderKind.Unknown ? KnownValues.Unknown : value.ToString();

    public static string Format(PlatformVendorKind value)
        => value switch
        {
            PlatformVendorKind.Siemens => "Siemens",
            PlatformVendorKind.SiemensIndustrialEdge => "Siemens Industrial Edge",
            PlatformVendorKind.Wago => "WAGO",
            PlatformVendorKind.PhoenixContact => "Phoenix Contact",
            PlatformVendorKind.BoschRexroth => "Bosch Rexroth",
            PlatformVendorKind.SchneiderElectric => "Schneider Electric",
            PlatformVendorKind.BAndR => "B&R",
            PlatformVendorKind.Opto22 => "Opto 22",
            PlatformVendorKind.Stratus => "Stratus",
            PlatformVendorKind.Unknown => KnownValues.Unknown,
            _ => value.ToString()
        };
}