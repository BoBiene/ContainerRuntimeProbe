using System.Text;
using System.Text.Json;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
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
        static string ValueOrUnknownString(string? value) => string.IsNullOrWhiteSpace(value) ? KnownValues.Unknown : value;
        static string ValueOrUnknownEnum<T>(T value) where T : struct, Enum => EqualityComparer<T>.Default.Equals(value, default) ? KnownValues.Unknown : value.ToString();
        static string FormatBytes(long? bytes)
        {
            if (bytes is null)
            {
                return KnownValues.Unknown;
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
        
        // Probe tool metadata section
        if (report.ProbeToolInfo is not null)
        {
            sb.AppendLine("## Probe Tool Information");
            sb.AppendLine($"- Version: {report.ProbeToolInfo.Version}");
            sb.AppendLine();
        }
        
        sb.AppendLine("## Summary");
        sb.AppendLine($"- IsContainerized: {ClassificationValueFormatter.Format(report.Classification.IsContainerized.Value)} ({report.Classification.IsContainerized.Confidence})");
        sb.AppendLine($"- ContainerRuntime: {ClassificationValueFormatter.Format(report.Classification.ContainerRuntime.Value)} ({report.Classification.ContainerRuntime.Confidence})");
        sb.AppendLine($"- Virtualization: {ClassificationValueFormatter.Format(report.Classification.Virtualization.Value)} ({report.Classification.Virtualization.Confidence})");
        sb.AppendLine($"- HostFamily: {ValueOrUnknownEnum(report.Classification.Host.Family.Value)} ({report.Classification.Host.Family.Confidence})");
        sb.AppendLine($"- HostType: {ClassificationValueFormatter.Format(report.Classification.Host.Type.Value)} ({report.Classification.Host.Type.Confidence})");
        sb.AppendLine($"- EnvironmentType: {ClassificationValueFormatter.Format(report.Classification.Environment.Type.Value)} ({report.Classification.Environment.Type.Confidence})");
        sb.AppendLine($"- RuntimeApi: {ClassificationValueFormatter.Format(report.Classification.RuntimeApi.Value)} ({report.Classification.RuntimeApi.Confidence})");
        sb.AppendLine($"- Orchestrator: {ClassificationValueFormatter.Format(report.Classification.Orchestrator.Value)} ({report.Classification.Orchestrator.Confidence})");
        sb.AppendLine($"- CloudProvider: {ClassificationValueFormatter.Format(report.Classification.CloudProvider.Value)} ({report.Classification.CloudProvider.Confidence})");
        sb.AppendLine($"- PlatformVendor: {ClassificationValueFormatter.Format(report.Classification.PlatformVendor.Value)} ({report.Classification.PlatformVendor.Confidence})");
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
        sb.AppendLine($"- Compiler: {FormatKernelBuild(report.Host.VisibleKernel.Compiler)}");
        sb.AppendLine($"- Compiler Raw: {ValueOrUnknownString(report.Host.VisibleKernel.Compiler?.Raw)}");
        sb.AppendLine($"- Compiler Distribution Hint: {ValueOrUnknownString(report.Host.VisibleKernel.Compiler?.DistributionHint)}");
        sb.AppendLine($"- Compiler Distribution Version Hint: {ValueOrUnknownString(report.Host.VisibleKernel.Compiler?.DistributionVersionHint)}");
        sb.AppendLine($"- Architecture: {ValueOrUnknownString(report.Host.VisibleKernel.RawArchitecture ?? report.Host.VisibleKernel.Architecture.ToString())}");
        sb.AppendLine($"- Confidence: {report.Host.VisibleKernel.Confidence}");
        sb.AppendLine();
        sb.AppendLine("### Virtualization");
        sb.AppendLine($"- Type: {ValueOrUnknownEnum(report.Host.Virtualization.Kind)}");
        sb.AppendLine($"- Platform Vendor: {ValueOrUnknownString(report.Host.Virtualization.PlatformVendor)}");
        sb.AppendLine($"- Confidence: {report.Host.Virtualization.Confidence}");
        sb.AppendLine();
        sb.AppendLine("### Underlying Host OS");
        sb.AppendLine($"- Family: {ValueOrUnknownEnum(report.Host.UnderlyingHostOs.Family)}");
        sb.AppendLine($"- Name: {ValueOrUnknownString(report.Host.UnderlyingHostOs.Name)}");
        sb.AppendLine($"- Version: {ValueOrUnknownString(report.Host.UnderlyingHostOs.Version)}");
        sb.AppendLine($"- Version Hint: {ValueOrUnknownString(report.Host.UnderlyingHostOs.VersionHint)}");
        sb.AppendLine($"- Source: {ValueOrUnknownEnum(report.Host.UnderlyingHostOs.Source)}");
        sb.AppendLine($"- Confidence: {report.Host.UnderlyingHostOs.Confidence}");
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
    }

    /// <summary>Renders a multi-line aligned text summary with one field per line and confidence indicators.</summary>
    public static string ToText(ContainerRuntimeReport report)
    {
        static string ValueOrUnknownEnum<T>(T value) where T : struct, Enum => EqualityComparer<T>.Default.Equals(value, default) ? KnownValues.Unknown : value.ToString();

        // ContainerOS: what /etc/os-release inside the container says.
        var containerOs = report.Host.ContainerImageOs.PrettyName
                       ?? report.Host.ContainerImageOs.Id
                       ?? KnownValues.Unknown;

        // HostOS: what the container runtime (Docker, etc.) reports as the host — no fallback to container OS.
        var runtimeHost = report.Host.RuntimeReportedHostOs;
        string hostOs;
        if (string.IsNullOrWhiteSpace(runtimeHost.Name))
        {
            hostOs = KnownValues.Unknown;
        }
        else if (!string.IsNullOrWhiteSpace(runtimeHost.Version)
                 && !runtimeHost.Name.Contains(runtimeHost.Version, StringComparison.OrdinalIgnoreCase))
        {
            hostOs = $"{runtimeHost.Name} {runtimeHost.Version}";
        }
        else
        {
            hostOs = runtimeHost.Name;
        }

        var underlyingHost = report.Host.UnderlyingHostOs.Family == OperatingSystemFamily.Unknown
            ? KnownValues.Unknown
            : report.Host.UnderlyingHostOs.Name
                ?? report.Host.UnderlyingHostOs.Family.ToString();

        var kernel = report.Host.VisibleKernel;
        var kernelVersion = string.IsNullOrWhiteSpace(kernel.Release)
            ? (string.IsNullOrWhiteSpace(kernel.Name) ? KnownValues.Unknown : kernel.Name)
            : string.IsNullOrWhiteSpace(kernel.Name)
                ? kernel.Release
                : $"{kernel.Name} {kernel.Release}";
        var kernelBuild = FormatKernelBuild(kernel.Compiler);
        var kernelHostOs = report.Host.UnderlyingHostOs.Source == UnderlyingHostOsSource.VisibleKernel
            ? underlyingHost
            : KnownValues.Unknown;

        // (key, value, optional confidence)
        (string Key, string Value, Confidence? Conf)[] fields =
        [
            ("IsContainerized", ClassificationValueFormatter.Format(report.Classification.IsContainerized.Value),   report.Classification.IsContainerized.Confidence),
            ("Runtime",         ClassificationValueFormatter.Format(report.Classification.ContainerRuntime.Value),   report.Classification.ContainerRuntime.Confidence),
            ("Virtualization",  ClassificationValueFormatter.Format(report.Classification.Virtualization.Value),     report.Classification.Virtualization.Confidence),
            ("HostFamily",      ValueOrUnknownEnum(report.Classification.Host.Family.Value),                        report.Classification.Host.Family.Confidence),
            ("HostType",        ClassificationValueFormatter.Format(report.Classification.Host.Type.Value),          report.Classification.Host.Type.Confidence),
            ("Environment",     ClassificationValueFormatter.Format(report.Classification.Environment.Type.Value),   report.Classification.Environment.Type.Confidence),
            ("RuntimeApi",      ClassificationValueFormatter.Format(report.Classification.RuntimeApi.Value),         report.Classification.RuntimeApi.Confidence),
            ("Orchestrator",    ClassificationValueFormatter.Format(report.Classification.Orchestrator.Value),       report.Classification.Orchestrator.Confidence),
            ("Cloud",           ClassificationValueFormatter.Format(report.Classification.CloudProvider.Value),      report.Classification.CloudProvider.Confidence),
            ("Vendor",          ClassificationValueFormatter.Format(report.Classification.PlatformVendor.Value),     report.Classification.PlatformVendor.Confidence),
            ("UnderlyingHost",  underlyingHost,                                 null),
            ("HostOS",          hostOs,                                         runtimeHost.Confidence),
            ("HostKernelOS",    kernelHostOs,                                   report.Host.UnderlyingHostOs.Source == UnderlyingHostOsSource.VisibleKernel ? report.Host.UnderlyingHostOs.Confidence : null),
            ("KernelBuild",     kernelBuild,                                    kernel.Compiler is null ? null : Confidence.Low),
            ("ContainerOS",     containerOs,                                    null),
            ("Kernel",          kernelVersion,                                  kernel.Confidence),
            ("HostFingerprint", report.Host.Fingerprint?.Value ?? "disabled",   null),
        ];

        var maxKeyLen = fields.Max(f => f.Key.Length);
        var sb = new StringBuilder();

        if (report.ProbeToolInfo is not null)
        {
            // Version already has a 7-char build-metadata hash (shortened at source).
            var header = $"Container Runtime Report  v{report.ProbeToolInfo.Version}";
            sb.AppendLine(header);
            sb.AppendLine(new string('-', header.Length));
        }

        foreach (var (key, value, conf) in fields)
        {
            var confSuffix = conf is not null && conf != Confidence.Unknown
                ? $"  [{conf}]"
                : string.Empty;
            sb.AppendLine($"{key.PadRight(maxKeyLen)} : {value}{confSuffix}");
        }

        return sb.ToString().TrimEnd();
    }

    private static string FormatHostOs(string? name, string? version)
    {
        if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(version))
        {
            return KnownValues.Unknown;
        }

        if (string.IsNullOrWhiteSpace(version) || (name?.Contains(version, StringComparison.OrdinalIgnoreCase) ?? false))
        {
            return string.IsNullOrWhiteSpace(name) ? KnownValues.Unknown : name;
        }

        return $"{name} {version}";
    }

    private static string FormatKernelBuild(KernelCompilerInfo? compiler)
    {
        if (compiler is null)
        {
            return KnownValues.Unknown;
        }

        var tool = JoinNonEmpty(compiler.Name, compiler.Version);
        var hint = FormatCompilerHint(compiler);
        if (!string.IsNullOrWhiteSpace(tool) && !string.IsNullOrWhiteSpace(hint))
        {
            return $"{tool} ({hint})";
        }

        if (!string.IsNullOrWhiteSpace(tool))
        {
            return tool;
        }

        if (!string.IsNullOrWhiteSpace(hint))
        {
            return hint;
        }

        return string.IsNullOrWhiteSpace(compiler.Raw) ? KnownValues.Unknown : compiler.Raw;
    }

    private static string? FormatCompilerHint(KernelCompilerInfo compiler)
    {
        if (string.IsNullOrWhiteSpace(compiler.DistributionHint))
        {
            return null;
        }

        return string.IsNullOrWhiteSpace(compiler.DistributionVersionHint)
            ? $"{compiler.DistributionHint} toolchain hint"
            : $"{compiler.DistributionHint} {compiler.DistributionVersionHint} toolchain hint";
    }

    private static string JoinNonEmpty(params string?[] values)
        => string.Join(' ', values.Where(value => !string.IsNullOrWhiteSpace(value)));
}
