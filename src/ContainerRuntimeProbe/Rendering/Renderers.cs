using System.Text;
using System.Text.Json;
using ContainerRuntimeProbe;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Rendering;

/// <summary>Renders <see cref="ContainerRuntimeReport"/> into JSON, Markdown, or compact text formats.</summary>
public static class ReportRenderer
{
    private static string ValueOrUnknownString(string? value) => string.IsNullOrWhiteSpace(value) ? KnownValues.Unknown : value;

    private static string ValueOrUnknownEnum<T>(T value) where T : struct, Enum
        => EqualityComparer<T>.Default.Equals(value, default) ? KnownValues.Unknown : value.ToString();

    private static string FormatBytes(long? bytes)
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

    /// <summary>Renders report to JSON using source-generated metadata.</summary>
    public static string ToJson(ContainerRuntimeReport report)
        => JsonSerializer.Serialize(
            report.Summary is null ? report with { Summary = report.GetSummary() } : report,
            ReportJsonContext.Default.ContainerRuntimeReport);

    /// <summary>Renders report as Markdown for support and diagnostics workflows.</summary>
    public static string ToMarkdown(ContainerRuntimeReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Container Runtime Report");
        
        // Probe tool metadata section
        if (report.ProbeToolInfo is not null)
        {
            sb.AppendLine("## Probe Tool Information");
            sb.AppendLine($"- Version: {report.ProbeToolInfo.Version}");
            sb.AppendLine($"- Git Commit: {ValueOrUnknownString(report.ProbeToolInfo.GitCommit)}");
            sb.AppendLine();
        }
        
        ReportSummaryRenderer.AppendMarkdown(sb, report);
        sb.AppendLine();
        AppendHostMarkdown(sb, report);
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
        AppendPlatformEvidenceMarkdown(sb, report.PlatformEvidence);
        sb.AppendLine();
        AppendTrustedPlatformsMarkdown(sb, report.TrustedPlatforms);
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
        var kernelVersion = FormatKernelSummary(kernel);
        var kernelBuild = FormatKernelBuild(kernel.Compiler);
        var kernelHostOs = report.Host.UnderlyingHostOs.Source == UnderlyingHostOsSource.VisibleKernel
            ? underlyingHost
            : KnownValues.Unknown;

        var fields = BuildTextFields(report, containerOs, underlyingHost, hostOs, kernelHostOs, kernelBuild, kernelVersion);

        var maxKeyLen = fields.Max(f => f.Key.Length);
        var sb = new StringBuilder();

        if (report.ProbeToolInfo is not null)
        {
            var versionWithCommit = string.IsNullOrWhiteSpace(report.ProbeToolInfo.GitCommit)
                ? report.ProbeToolInfo.Version
                : $"{report.ProbeToolInfo.Version} ({report.ProbeToolInfo.GitCommit})";
            var header = $"Container Runtime Report  v{versionWithCommit}";
            sb.AppendLine(header);
            sb.AppendLine(new string('-', header.Length));
        }

        ReportSummaryRenderer.AppendText(sb, report);
        sb.AppendLine("Details");
        sb.AppendLine("-------");
        foreach (var (key, value, conf) in fields)
        {
            var confSuffix = conf is not null && conf != Confidence.Unknown
                ? $"  [{conf}]"
                : string.Empty;
            sb.AppendLine($"{key.PadRight(maxKeyLen)} : {value}{confSuffix}");
        }

        AppendPlatformEvidenceText(sb, report.PlatformEvidence);
        AppendTrustedPlatformsText(sb, report.TrustedPlatforms);

        return sb.ToString().TrimEnd();
    }

    private static void AppendHostMarkdown(StringBuilder sb, ContainerRuntimeReport report)
    {
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
        sb.AppendLine($"- Architecture: {ValueOrUnknownString(report.Host.Hardware.RawArchitecture ?? report.Host.Hardware.Architecture.ToString())}");
        sb.AppendLine($"- CPU: {ValueOrUnknownString(report.Host.Hardware.Cpu.ModelName ?? report.Host.Hardware.Cpu.Family)}, {ValueOrUnknownString(report.Host.Hardware.Cpu.LogicalProcessorCount?.ToString())} logical processors");
        sb.AppendLine($"- Memory: {FormatBytes(report.Host.Hardware.Memory.MemTotalBytes)} visible, cgroup limit: {ValueOrUnknownString(report.Host.Hardware.Memory.CgroupMemoryLimitRaw ?? FormatBytes(report.Host.Hardware.Memory.CgroupMemoryLimitBytes))}");
        sb.AppendLine($"- Machine Type: {ValueOrUnknownString(report.Host.Hardware.CloudMachineType)}");
        sb.AppendLine();
        sb.AppendLine("### Platform / DMI");
        sb.AppendLine($"- System Vendor: {ValueOrUnknownString(report.Host.Hardware.Dmi.SystemVendor)}");
        sb.AppendLine($"- Product Name: {ValueOrUnknownString(report.Host.Hardware.Dmi.ProductName)}");
        sb.AppendLine($"- Product Family: {ValueOrUnknownString(report.Host.Hardware.Dmi.ProductFamily)}");
        sb.AppendLine($"- Product Version: {ValueOrUnknownString(report.Host.Hardware.Dmi.ProductVersion)}");
        sb.AppendLine($"- Board Vendor: {ValueOrUnknownString(report.Host.Hardware.Dmi.BoardVendor)}");
        sb.AppendLine($"- Board Name: {ValueOrUnknownString(report.Host.Hardware.Dmi.BoardName)}");
        sb.AppendLine($"- Chassis Vendor: {ValueOrUnknownString(report.Host.Hardware.Dmi.ChassisVendor)}");
        sb.AppendLine($"- BIOS Vendor: {ValueOrUnknownString(report.Host.Hardware.Dmi.BiosVendor)}");
        sb.AppendLine($"- Confidence: {report.Host.Hardware.Dmi.Confidence}");
        sb.AppendLine();
        sb.AppendLine("### Device Tree");
        sb.AppendLine($"- Model: {ValueOrUnknownString(report.Host.Hardware.DeviceTree.Model)}");
        sb.AppendLine($"- Compatible: {ValueOrUnknownString(report.Host.Hardware.DeviceTree.Compatible)}");
        sb.AppendLine($"- Confidence: {report.Host.Hardware.DeviceTree.Confidence}");
        sb.AppendLine();
        AppendDiagnosticFingerprintsMarkdown(sb, report.Host.DiagnosticFingerprints);
        sb.AppendLine();
        AppendIdentityAnchorsMarkdown(sb, report.Host.IdentityAnchors);
        sb.AppendLine();
    }

    private static void AppendDiagnosticFingerprintsMarkdown(StringBuilder sb, IReadOnlyList<DiagnosticFingerprint> fingerprints)
    {
        sb.AppendLine("### Diagnostic Fingerprints");
        var diagnosticFingerprint = fingerprints.FirstOrDefault();
        if (diagnosticFingerprint is null)
        {
            sb.AppendLine("- Diagnostic fingerprint generation disabled.");
            return;
        }

        sb.AppendLine($"- Purpose: {diagnosticFingerprint.Purpose}");
        sb.AppendLine($"- Algorithm: {diagnosticFingerprint.Algorithm}");
        sb.AppendLine($"- Value: {diagnosticFingerprint.Value}");
        sb.AppendLine($"- Stability: {diagnosticFingerprint.Stability}");
        sb.AppendLine($"- Stability Level: {diagnosticFingerprint.StabilityLevel}");
        sb.AppendLine($"- Included Signals: {diagnosticFingerprint.IncludedSignalCount}");
        sb.AppendLine($"- Excluded Sensitive Signals: {diagnosticFingerprint.ExcludedSensitiveSignalCount}");
        foreach (var warning in diagnosticFingerprint.Warnings)
        {
            sb.AppendLine($"- Warning: {warning}");
        }
    }

    private static void AppendIdentityAnchorsMarkdown(StringBuilder sb, IReadOnlyList<IdentityAnchor> anchors)
    {
        sb.AppendLine("### Identity Anchors");
        if (anchors.Count == 0)
        {
            sb.AppendLine("- No explicit identity anchors were derived from the visible environment.");
            return;
        }

        foreach (var anchor in anchors)
        {
            sb.AppendLine($"- Kind: {anchor.Kind}");
            sb.AppendLine($"- Value: {anchor.Value}");
            sb.AppendLine($"- Scope: {anchor.Scope}");
            sb.AppendLine($"- Binding Suitability: {anchor.BindingSuitability}");
            sb.AppendLine($"- Strength: {anchor.Strength}");
            sb.AppendLine($"- Sensitivity: {anchor.Sensitivity}");
            foreach (var reason in anchor.Reasons)
            {
                sb.AppendLine($"- Reason: {reason}");
            }

            foreach (var warning in anchor.Warnings)
            {
                sb.AppendLine($"- Warning: {warning}");
            }
        }
    }

    private static string FormatIdentityAnchorSummary(IReadOnlyList<IdentityAnchor> anchors)
        => anchors.Count == 0
            ? "none"
            : string.Join("; ", anchors.Select(anchor => $"{anchor.Kind}:{anchor.Strength}/{anchor.BindingSuitability}={anchor.Value}"));

    private static IReadOnlyList<(string Key, string Value, Confidence? Conf)> BuildTextFields(
        ContainerRuntimeReport report,
        string containerOs,
        string underlyingHost,
        string hostOs,
        string kernelHostOs,
        string kernelBuild,
        string kernelVersion)
        =>
        [
            ("IsContainerized", ClassificationValueFormatter.Format(report.Classification.IsContainerized.Value), report.Classification.IsContainerized.Confidence),
            ("Runtime", ClassificationValueFormatter.Format(report.Classification.ContainerRuntime.Value), report.Classification.ContainerRuntime.Confidence),
            ("Virtualization", ClassificationValueFormatter.Format(report.Classification.Virtualization.Value), report.Classification.Virtualization.Confidence),
            ("HostFamily", ValueOrUnknownEnum(report.Classification.Host.Family.Value), report.Classification.Host.Family.Confidence),
            ("HostType", ClassificationValueFormatter.Format(report.Classification.Host.Type.Value), report.Classification.Host.Type.Confidence),
            ("Environment", ClassificationValueFormatter.Format(report.Classification.Environment.Type.Value), report.Classification.Environment.Type.Confidence),
            ("RuntimeApi", ClassificationValueFormatter.Format(report.Classification.RuntimeApi.Value), report.Classification.RuntimeApi.Confidence),
            ("Orchestrator", ClassificationValueFormatter.Format(report.Classification.Orchestrator.Value), report.Classification.Orchestrator.Confidence),
            ("Cloud", ClassificationValueFormatter.Format(report.Classification.CloudProvider.Value), report.Classification.CloudProvider.Confidence),
            ("Vendor", ClassificationValueFormatter.Format(report.Classification.PlatformVendor.Value), report.Classification.PlatformVendor.Confidence),
            ("Architecture", report.Host.Hardware.RawArchitecture ?? ValueOrUnknownEnum(report.Host.Hardware.Architecture), null),
            ("HardwareVendor", ValueOrUnknownString(report.Host.Hardware.Dmi.SystemVendor), report.Host.Hardware.Dmi.Confidence),
            ("ProductName", ValueOrUnknownString(report.Host.Hardware.Dmi.ProductName), report.Host.Hardware.Dmi.Confidence),
            ("DeviceTreeModel", ValueOrUnknownString(report.Host.Hardware.DeviceTree.Model), report.Host.Hardware.DeviceTree.Confidence),
            ("UnderlyingHost", underlyingHost, null),
            ("HostOS", hostOs, report.Host.RuntimeReportedHostOs.Confidence),
            ("HostKernelOS", kernelHostOs, report.Host.UnderlyingHostOs.Source == UnderlyingHostOsSource.VisibleKernel ? report.Host.UnderlyingHostOs.Confidence : null),
            ("KernelBuild", kernelBuild, report.Host.VisibleKernel.Compiler is null ? null : Confidence.Low),
            ("ContainerOS", containerOs, null),
            ("Kernel", kernelVersion, report.Host.VisibleKernel.Confidence),
            ("DiagnosticFingerprint", report.Host.DiagnosticFingerprints.FirstOrDefault()?.Value ?? "disabled", null),
            ("IdentityAnchors", FormatIdentityAnchorSummary(report.Host.IdentityAnchors), null)
        ];

    private static string FormatKernelSummary(VisibleKernelInfo kernel)
    {
        if (string.IsNullOrWhiteSpace(kernel.Release))
        {
            return string.IsNullOrWhiteSpace(kernel.Name) ? KnownValues.Unknown : kernel.Name;
        }

        if (string.IsNullOrWhiteSpace(kernel.Name))
        {
            return kernel.Release;
        }

        return $"{kernel.Name} {kernel.Release}";
    }

    private static void AppendPlatformEvidenceMarkdown(StringBuilder sb, IReadOnlyList<PlatformEvidenceSummary>? platformEvidence)
    {
        sb.AppendLine("## Platform Evidence");
        var relevantEvidence = platformEvidence?
            .Where(summary => summary.EvidenceLevel != PlatformEvidenceLevel.None)
            .ToArray() ?? [];

        if (relevantEvidence.Length == 0)
        {
            sb.AppendLine("- None.");
            return;
        }

        foreach (var summary in relevantEvidence)
        {
            sb.AppendLine($"### {summary.PlatformKey}");
            sb.AppendLine($"- Level: {summary.EvidenceLevel}");
            sb.AppendLine($"- Score: {summary.Score}");
            sb.AppendLine($"- Confidence: {summary.Confidence}");
            foreach (var item in summary.Evidence)
            {
                sb.AppendLine($"- Evidence [{item.Type}] {item.Key}: {item.Value} ({item.Confidence})");
            }

            foreach (var warning in summary.Warnings)
            {
                sb.AppendLine($"- Warning: {warning}");
            }
        }
    }

    private static void AppendTrustedPlatformsMarkdown(StringBuilder sb, IReadOnlyList<TrustedPlatformSummary>? trustedPlatforms)
    {
        sb.AppendLine("## Trusted Platforms");
        var relevantPlatforms = trustedPlatforms?
            .Where(summary => summary.State != TrustedPlatformState.None)
            .ToArray() ?? [];

        if (relevantPlatforms.Length == 0)
        {
            sb.AppendLine("- None.");
            return;
        }

        foreach (var summary in relevantPlatforms)
        {
            sb.AppendLine($"### {summary.PlatformKey}");
            sb.AppendLine($"- State: {summary.State}");
            sb.AppendLine($"- Verification Level: {summary.VerificationLevel}");
            sb.AppendLine($"- Verification Method: {summary.VerificationMethod ?? KnownValues.Unknown}");
            sb.AppendLine($"- Subject: {summary.Subject ?? KnownValues.Unknown}");
            foreach (var claim in summary.Claims)
            {
                sb.AppendLine($"- Claim [{claim.Scope}] {claim.Type}: {claim.Value} ({claim.Confidence})");
            }

            foreach (var item in summary.Evidence)
            {
                sb.AppendLine($"- Evidence [{item.SourceType}] {item.Key}: {item.Value} ({item.Confidence})");
            }

            foreach (var warning in summary.Warnings)
            {
                sb.AppendLine($"- Warning: {warning}");
            }
        }
    }

    private static void AppendPlatformEvidenceText(StringBuilder sb, IReadOnlyList<PlatformEvidenceSummary>? platformEvidence)
    {
        var relevantEvidence = platformEvidence?
            .Where(summary => summary.EvidenceLevel != PlatformEvidenceLevel.None)
            .ToArray() ?? [];

        if (relevantEvidence.Length == 0)
        {
            return;
        }

        sb.AppendLine();
        foreach (var summary in relevantEvidence)
        {
            sb.AppendLine($"PlatformEvidence : {summary.PlatformKey}  [{summary.EvidenceLevel}, score={summary.Score}, {summary.Confidence}]");
        }
    }

    private static void AppendTrustedPlatformsText(StringBuilder sb, IReadOnlyList<TrustedPlatformSummary>? trustedPlatforms)
    {
        var relevantPlatforms = trustedPlatforms?
            .Where(summary => summary.State != TrustedPlatformState.None)
            .ToArray() ?? [];

        if (relevantPlatforms.Length == 0)
        {
            return;
        }

        sb.AppendLine();
        foreach (var summary in relevantPlatforms)
        {
            sb.AppendLine($"TrustedPlatform  : {summary.PlatformKey}  [{summary.State}, level={summary.VerificationLevel}, {summary.VerificationMethod ?? KnownValues.Unknown}]");
        }
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
