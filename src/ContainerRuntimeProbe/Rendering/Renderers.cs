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
        sb.AppendLine();
        sb.AppendLine("## Summary");
        sb.AppendLine($"- Environment classification: {report.Containerization.Value} ({report.Containerization.Confidence})");
        sb.AppendLine($"- Runtime classification: {report.Runtime.Value} ({report.Runtime.Confidence})");
        sb.AppendLine($"- Orchestrator classification: {report.Orchestrator.Value} ({report.Orchestrator.Confidence})");
        sb.AppendLine($"- Cloud classification: {report.Cloud.Value} ({report.Cloud.Confidence})");
        sb.AppendLine();
        sb.AppendLine("## Raw Evidence");
        foreach (var probe in report.Probes)
        {
            sb.AppendLine($"### {probe.ProbeId}");
            foreach (var item in probe.Evidence)
            {
                sb.AppendLine($"- {item.Key}: {item.Value}");
            }

            if (probe.Failure is not null)
            {
                sb.AppendLine($"- failure: {probe.Failure.Error}");
            }
        }

        return sb.ToString();
    }

    public static string ToText(ContainerRuntimeReport report) =>
        $"Container={report.Containerization.Value} ({report.Containerization.Confidence}), Runtime={report.Runtime.Value}, Orchestrator={report.Orchestrator.Value}, Cloud={report.Cloud.Value}";
}
