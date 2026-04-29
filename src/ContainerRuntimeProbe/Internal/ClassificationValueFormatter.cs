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
            PlatformVendorKind.SiemensIndustrialEdge => "Siemens Industrial Edge",
            PlatformVendorKind.Unknown => KnownValues.Unknown,
            _ => value.ToString()
        };
}