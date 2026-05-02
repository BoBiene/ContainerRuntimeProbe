using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe;

/// <summary>Builds broad summary variant information for a normalized report.</summary>
public static partial class ContainerRuntimeReportSummaryExtensions
{
    /// <summary>Returns the broad summary variant for a normalized report.</summary>
    public static SummaryVariantKind GetSummaryVariant(this ContainerRuntimeReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        if (report.Classification.Orchestrator.Value == OrchestratorKind.Kubernetes)
        {
            return SummaryVariantKind.KubernetesWorkload;
        }

        if (report.Classification.IsContainerized.Value == ContainerizationKind.@False && IsWindowsHost(report))
        {
            return SummaryVariantKind.WindowsBare;
        }

        if (report.Classification.IsContainerized.Value == ContainerizationKind.@True && IsIndustrialPlatform(report))
        {
            return SummaryVariantKind.IndustrialContainer;
        }

        if (report.Classification.IsContainerized.Value == ContainerizationKind.@True)
        {
            return SummaryVariantKind.StandaloneContainer;
        }

        return SummaryVariantKind.Unknown;
    }

    private static bool IsWindowsHost(ContainerRuntimeReport report)
        => report.Host.RuntimeReportedHostOs.Family == OperatingSystemFamily.Windows
           || report.Host.UnderlyingHostOs.Family == OperatingSystemFamily.Windows
           || report.Host.ContainerImageOs.Family == OperatingSystemFamily.Windows;

    private static bool IsIndustrialPlatform(ContainerRuntimeReport report)
    {
        var vendor = report.Classification.PlatformVendor.Value;
        if (vendor is PlatformVendorKind.Siemens
            or PlatformVendorKind.SiemensIndustrialEdge
            or PlatformVendorKind.Wago
            or PlatformVendorKind.Beckhoff
            or PlatformVendorKind.PhoenixContact
            or PlatformVendorKind.Advantech
            or PlatformVendorKind.Moxa
            or PlatformVendorKind.BoschRexroth
            or PlatformVendorKind.SchneiderElectric
            or PlatformVendorKind.BAndR
            or PlatformVendorKind.Opto22
            or PlatformVendorKind.Stratus)
        {
            return true;
        }

        return report.TrustedPlatforms?.Any(summary => string.Equals(summary.PlatformKey, "siemens-ied-runtime", StringComparison.Ordinal)) == true;
    }
}