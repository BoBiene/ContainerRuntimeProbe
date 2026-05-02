using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe;

/// <summary>Builds the structured neutral summary attached to a normalized report.</summary>
public static partial class ContainerRuntimeReportSummaryExtensions
{
    /// <summary>Returns the complete structured summary for a normalized report.</summary>
    public static ReportSummary GetSummary(this ContainerRuntimeReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return new ReportSummary(report.GetEnvironmentSummary(), report.GetIdentitySummary());
    }
}