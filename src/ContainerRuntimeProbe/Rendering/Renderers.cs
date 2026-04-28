using System.Text;
using System.Text.Json;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Rendering;

public static class ReportRenderer
{
    public static string ToJson(ContainerRuntimeReport report) => JsonSerializer.Serialize(report, ReportJsonContext.Default.ContainerRuntimeReport);

    public static string ToMarkdown(ContainerRuntimeReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Container Runtime Report");
        sb.AppendLine("## Summary");
        sb.AppendLine($"- IsContainerized: {report.Classification.IsContainerized.Value} ({report.Classification.IsContainerized.Confidence})");
        sb.AppendLine($"- ContainerRuntime: {report.Classification.ContainerRuntime.Value} ({report.Classification.ContainerRuntime.Confidence})");
        sb.AppendLine($"- RuntimeApi: {report.Classification.RuntimeApi.Value} ({report.Classification.RuntimeApi.Confidence})");
        sb.AppendLine($"- Orchestrator: {report.Classification.Orchestrator.Value} ({report.Classification.Orchestrator.Confidence})");
        sb.AppendLine($"- CloudProvider: {report.Classification.CloudProvider.Value} ({report.Classification.CloudProvider.Confidence})");
        sb.AppendLine($"- PlatformVendor: {report.Classification.PlatformVendor.Value} ({report.Classification.PlatformVendor.Confidence})");
        sb.AppendLine("## Security and Limitations");
        foreach (var w in report.SecurityWarnings) sb.AppendLine($"- [{w.Code}] {w.Message}");
        sb.AppendLine("## Raw Evidence");
        foreach (var probe in report.Probes)
        {
            sb.AppendLine($"### {probe.ProbeId} ({probe.Outcome})");
            if (!string.IsNullOrWhiteSpace(probe.Message)) sb.AppendLine($"- message: {probe.Message}");
            foreach (var item in probe.Evidence.Take(80)) sb.AppendLine($"- {item.Key}: {item.Value}");
        }

        return sb.ToString();
    }

    public static string ToText(ContainerRuntimeReport report)
        => $"IsContainerized={report.Classification.IsContainerized.Value}, Runtime={report.Classification.ContainerRuntime.Value}, RuntimeApi={report.Classification.RuntimeApi.Value}, Orchestrator={report.Classification.Orchestrator.Value}, Cloud={report.Classification.CloudProvider.Value}, Vendor={report.Classification.PlatformVendor.Value}";
}
