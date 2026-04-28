using System.Text;
using System.Text.Json;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Rendering;

/// <summary>Renders <see cref="ContainerRuntimeReport"/> into JSON, Markdown, or compact text formats.</summary>
public static class ReportRenderer
{
    /// <summary>Renders report to JSON using source-generated metadata.</summary>
    public static string ToJson(ContainerRuntimeReport report) => JsonSerializer.Serialize(report, ReportJsonContext.Default.ContainerRuntimeReport);

    /// <summary>Renders report as Markdown for support and diagnostics workflows.</summary>
    public static string ToMarkdown(ContainerRuntimeReport report)
    {
        static string ValueOrUnknownString(string? value) => string.IsNullOrWhiteSpace(value) ? "Unknown" : value;
        static string ValueOrUnknownEnum<T>(T value) where T : struct, Enum => EqualityComparer<T>.Default.Equals(value, default) ? "Unknown" : value.ToString();
        static string FormatBytes(long? bytes)
        {
            if (bytes is null)
            {
                return "Unknown";
            }

            if (bytes < 1024)
            {
                return $"{bytes} B";
            }

            var units = new[] { "KB", "MB", "GB", "TB" };
            double value = bytes.Value;
            var index = -1;
            do
            {
                value /= 1024d;
                index++;
            }
            while (value >= 1024d && index < units.Length - 1);

            return $"{value:0.##} {units[index]}";
        }

        var sb = new StringBuilder();
        sb.AppendLine("# Container Runtime Report");
        sb.AppendLine("## Summary");
        sb.AppendLine($"- IsContainerized: {report.Classification.IsContainerized.Value} ({report.Classification.IsContainerized.Confidence})");
        sb.AppendLine($"- ContainerRuntime: {report.Classification.ContainerRuntime.Value} ({report.Classification.ContainerRuntime.Confidence})");
        sb.AppendLine($"- RuntimeApi: {report.Classification.RuntimeApi.Value} ({report.Classification.RuntimeApi.Confidence})");
        sb.AppendLine($"- Orchestrator: {report.Classification.Orchestrator.Value} ({report.Classification.Orchestrator.Confidence})");
        sb.AppendLine($"- CloudProvider: {report.Classification.CloudProvider.Value} ({report.Classification.CloudProvider.Confidence})");
        sb.AppendLine($"- PlatformVendor: {report.Classification.PlatformVendor.Value} ({report.Classification.PlatformVendor.Confidence})");
        sb.AppendLine();
        sb.AppendLine("## Host OS / Node");
        sb.AppendLine("### Container Image OS");
        sb.AppendLine($"- Family: {ValueOrUnknownEnum(report.Host.ContainerImageOs.Family)}");
        sb.AppendLine($"- ID: {ValueOrUnknownString(report.Host.ContainerImageOs.Id)}");
        sb.AppendLine($"- Version: {ValueOrUnknownString(report.Host.ContainerImageOs.Version ?? report.Host.ContainerImageOs.VersionId)}");
        sb.AppendLine($"- Pretty Name: {ValueOrUnknownString(report.Host.ContainerImageOs.PrettyName)}");
        sb.AppendLine($"- Architecture: {ValueOrUnknownEnum(report.Host.ContainerImageOs.Architecture)}");
        sb.AppendLine($"- Confidence: {report.Host.ContainerImageOs.Confidence}");
        sb.AppendLine();
        sb.AppendLine("### Visible Kernel");
        sb.AppendLine($"- Name: {ValueOrUnknownString(report.Host.VisibleKernel.Name)}");
        sb.AppendLine($"- Release: {ValueOrUnknownString(report.Host.VisibleKernel.Release)}");
        sb.AppendLine($"- Flavor: {ValueOrUnknownEnum(report.Host.VisibleKernel.Flavor)}");
        sb.AppendLine($"- Architecture: {ValueOrUnknownString(report.Host.VisibleKernel.RawArchitecture ?? report.Host.VisibleKernel.Architecture.ToString())}");
        sb.AppendLine($"- Confidence: {report.Host.VisibleKernel.Confidence}");
        sb.AppendLine();
        sb.AppendLine("### Runtime-Reported Host OS");
        sb.AppendLine($"- Source: {ValueOrUnknownEnum(report.Host.RuntimeReportedHostOs.Source)}");
        sb.AppendLine($"- OS: {FormatHostOs(report.Host.RuntimeReportedHostOs.Name, report.Host.RuntimeReportedHostOs.Version)}");
        sb.AppendLine($"- Kernel: {ValueOrUnknownString(report.Host.RuntimeReportedHostOs.KernelVersion)}");
        sb.AppendLine($"- Architecture: {ValueOrUnknownEnum(report.Host.RuntimeReportedHostOs.Architecture)}");
        sb.AppendLine($"- Confidence: {report.Host.RuntimeReportedHostOs.Confidence}");
        sb.AppendLine();
        sb.AppendLine("### Host Hardware Signals");
        sb.AppendLine($"- CPU: {ValueOrUnknownString(report.Host.Hardware.Cpu.ModelName ?? report.Host.Hardware.Cpu.Family)}, {ValueOrUnknownString(report.Host.Hardware.Cpu.LogicalProcessorCount?.ToString())} logical processors");
        sb.AppendLine($"- Memory: {FormatBytes(report.Host.Hardware.Memory.MemTotalBytes)} visible, cgroup limit: {ValueOrUnknownString(report.Host.Hardware.Memory.CgroupMemoryLimitRaw ?? FormatBytes(report.Host.Hardware.Memory.CgroupMemoryLimitBytes))}");
        sb.AppendLine($"- Machine Type: {ValueOrUnknownString(report.Host.Hardware.CloudMachineType)}");
        sb.AppendLine();
        sb.AppendLine("### Host Fingerprint");
        if (report.Host.Fingerprint is null)
        {
            sb.AppendLine("- Fingerprint generation disabled.");
        }
        else
        {
            sb.AppendLine($"- Algorithm: {report.Host.Fingerprint.Algorithm}");
            sb.AppendLine($"- Value: {report.Host.Fingerprint.Value}");
            sb.AppendLine($"- Stability: {report.Host.Fingerprint.Stability}");
            sb.AppendLine($"- Included Signals: {report.Host.Fingerprint.IncludedSignalCount}");
            sb.AppendLine($"- Excluded Sensitive Signals: {report.Host.Fingerprint.ExcludedSensitiveSignalCount}");
            foreach (var warning in report.Host.Fingerprint.Warnings)
            {
                sb.AppendLine($"- Warning: {warning}");
            }
        }
        sb.AppendLine();
        sb.AppendLine("## Security and Limitations");
        if (report.SecurityWarnings.Count == 0)
        {
            sb.AppendLine("- None detected by current probes.");
        }
        else
        {
            foreach (var w in report.SecurityWarnings) sb.AppendLine($"- [{w.Code}] {w.Message}");
        }

        sb.AppendLine();
        sb.AppendLine("## Raw Evidence");
        foreach (var probe in report.Probes)
        {
            sb.AppendLine($"### {probe.ProbeId} ({probe.Outcome})");
            if (!string.IsNullOrWhiteSpace(probe.Message)) sb.AppendLine($"- message: {probe.Message}");
            foreach (var item in probe.Evidence.Take(80)) sb.AppendLine($"- {item.Key}: {item.Value}");
        }

        return sb.ToString();

        static string FormatHostOs(string? name, string? version)
        {
            if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(version))
            {
                return "Unknown";
            }

            if (string.IsNullOrWhiteSpace(version) || (name?.Contains(version, StringComparison.OrdinalIgnoreCase) ?? false))
            {
                return ValueOrUnknownString(name);
            }

            return $"{ValueOrUnknownString(name)} {version}";
        }
    }

    /// <summary>Renders a compact one-line textual summary.</summary>
    public static string ToText(ContainerRuntimeReport report)
        => $"IsContainerized={report.Classification.IsContainerized.Value}, Runtime={report.Classification.ContainerRuntime.Value}, RuntimeApi={report.Classification.RuntimeApi.Value}, Orchestrator={report.Classification.Orchestrator.Value}, Cloud={report.Classification.CloudProvider.Value}, Vendor={report.Classification.PlatformVendor.Value}, HostOS={(report.Host.RuntimeReportedHostOs.Name ?? report.Host.ContainerImageOs.PrettyName ?? "Unknown")}, HostFingerprint={(report.Host.Fingerprint?.Value ?? "disabled")}";
}
