using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Rendering;

/// <summary>Renders dense compact runtime samples, sample JSON, and GitHub issue prefill artifacts.</summary>
public static class RuntimeSampleRenderer
{
    private const string CompactFormatVersion = "crp1";
    private const string DefaultTemplate = "runtime-sample.yml";
    private const string DefaultRepository = "BoBiene/ContainerRuntimeProbe";
    private static readonly Regex SafeTokenRegex = new("^[A-Za-z0-9._:-]+$", RegexOptions.Compiled);

    /// <summary>Builds sample artifacts from a report.</summary>
    public static RuntimeSampleArtifacts Build(ContainerRuntimeReport report, RuntimeSampleOptions? options = null)
    {
        options ??= new RuntimeSampleOptions();

        var environmentKind = InferEnvironmentKind(report);
        var scenarioName = string.IsNullOrWhiteSpace(options.Scenario) ? InferScenarioName(report) : NormalizeScenario(options.Scenario!);
        var importantSignals = BuildImportantSignals(report);
        var samplePayload = BuildSamplePayload(report, options, environmentKind, scenarioName, importantSignals);

        var compactData = BuildCompactSampleData(report, samplePayload, importantSignals);
        var renderedUrl = RenderUrlArtifacts(report, options, scenarioName, compactData, samplePayload);
        var compactSample = RenderCompactSample(compactData, renderedUrl.RenderOptions);
        var document = new RuntimeSampleDocument(
            "https://github.com/BoBiene/ContainerRuntimeProbe/schemas/runtime-sample.v1.json",
            "1.0",
            CompactFormatVersion,
            compactSample,
            new RuntimeSampleToolInfo("ContainerRuntimeProbe", GetToolVersion()),
            samplePayload);

        var compactBody = BuildIssueBody(report, compactSample, scenarioName, samplePayload, expanded: false, options.Expected);
        var expandedBody = BuildIssueBody(report, compactSample, scenarioName, samplePayload, expanded: true, options.Expected);

        return new RuntimeSampleArtifacts(
            compactSample,
            scenarioName,
            compactBody,
            expandedBody,
            renderedUrl.Url,
            renderedUrl.Warnings,
            document,
            BuildSummaryLines(report, scenarioName, samplePayload));
    }

    /// <summary>Renders sample JSON.</summary>
    public static string ToJson(RuntimeSampleArtifacts artifacts)
        => JsonSerializer.Serialize(artifacts.Document, SampleJsonContext.Default.RuntimeSampleDocument);

    /// <summary>Renders the compact markdown issue body.</summary>
    public static string ToMarkdown(RuntimeSampleArtifacts artifacts, string bodyFormat = "compact")
        => string.Equals(bodyFormat, "expanded", StringComparison.OrdinalIgnoreCase)
            ? artifacts.ExpandedBody
            : artifacts.CompactBody;

    /// <summary>Renders the default console output for the sample command.</summary>
    public static string ToConsoleText(RuntimeSampleArtifacts artifacts)
    {
        var sb = new StringBuilder();
        sb.AppendLine("ContainerRuntimeProbe sample created.");
        sb.AppendLine();
        sb.AppendLine("Compact sample:");
        sb.AppendLine(artifacts.CompactSample);
        sb.AppendLine();
        sb.AppendLine("Summary:");
        foreach (var line in artifacts.SummaryLines)
        {
            sb.AppendLine(line);
        }

        sb.AppendLine();
        sb.AppendLine("Open this URL to submit the sample:");
        sb.AppendLine(artifacts.PrefillUrl);
        if (artifacts.UrlWarnings.Count > 0)
        {
            sb.AppendLine();
            foreach (var warning in artifacts.UrlWarnings)
            {
                sb.AppendLine($"Warning: {warning}");
            }
        }

        sb.AppendLine();
        sb.AppendLine("Optional: attach the full redacted report for better detection improvements:");
        sb.AppendLine("docker run --rm ghcr.io/bobiene/container-runtime-probe:latest json > my-report.json");
        sb.AppendLine("container-runtime-probe json > my-report.json");
        sb.AppendLine();
        sb.AppendLine("The compact sample is enough for triage. The full report helps maintainers add better detection rules.");
        sb.AppendLine("Review my-report.json before uploading.");
        return sb.ToString().TrimEnd();
    }

    internal static string RenderCompactSample(CompactSampleData sample, CompactRenderOptions options)
    {
        var sections = new List<string>
        {
            CompactFormatVersion,
            $"cls={string.Join(',', sample.Classification)}",
            $"conf={string.Join(',', sample.Confidence)}",
            $"host={string.Join(',', BuildHostTokens(sample.Host, options))}"
        };

        var hardware = BuildHardwareTokens(sample.Hardware, options);
        if (hardware.Count > 0)
        {
            sections.Add($"hw={string.Join(',', hardware)}");
        }

        sections.Add($"fp={string.Join(',', BuildFingerprintTokens(sample.Fingerprint, options))}");
        sections.Add($"p={string.Join(',', sample.ProbeOutcomes)}");

        var signals = BuildSignalTokens(sample.Signals, options);
        if (signals.Count > 0)
        {
            sections.Add($"sig={string.Join(',', signals)}");
        }

        sections.Add($"sec={string.Join(',', sample.SecurityWarnings)}");
        return string.Join(';', sections);
    }

    internal static CompactRuntimeSampleParseResult ParseCompactSample(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return new CompactRuntimeSampleParseResult(false, string.Empty, new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal), ["Sample is empty."]);
        }

        var parts = value.Split(';', StringSplitOptions.None);
        if (parts.Length == 0 || !string.Equals(parts[0], CompactFormatVersion, StringComparison.Ordinal))
        {
            return new CompactRuntimeSampleParseResult(false, parts.Length == 0 ? string.Empty : parts[0], new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal), ["Unsupported compact sample version."]);
        }

        var knownSections = new HashSet<string>(StringComparer.Ordinal) { "cls", "conf", "host", "hw", "fp", "p", "sig", "sec" };
        var parsed = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        var diagnostics = new List<string>();
        var valid = true;

        foreach (var part in parts.Skip(1))
        {
            if (string.IsNullOrWhiteSpace(part))
            {
                diagnostics.Add("Empty section encountered.");
                valid = false;
                continue;
            }

            var separator = part.IndexOf('=');
            if (separator <= 0 || separator == part.Length - 1)
            {
                diagnostics.Add($"Malformed section '{part}'.");
                valid = false;
                continue;
            }

            var key = part[..separator];
            var rawValue = part[(separator + 1)..];
            if (!knownSections.Contains(key))
            {
                diagnostics.Add($"Unknown section '{key}'.");
            }

            if (parsed.ContainsKey(key))
            {
                diagnostics.Add($"Duplicate section '{key}'.");
                valid = false;
                continue;
            }

            var tokens = rawValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (tokens.Length == 0)
            {
                diagnostics.Add($"Section '{key}' is empty.");
                valid = false;
                continue;
            }

            var safeTokens = new List<string>(tokens.Length);
            foreach (var token in tokens)
            {
                if (token.Length > 80 || !SafeTokenRegex.IsMatch(token) || token.Contains("http", StringComparison.OrdinalIgnoreCase) || token.Contains("token", StringComparison.OrdinalIgnoreCase))
                {
                    diagnostics.Add($"Suspicious token '{token}' in section '{key}'.");
                    valid = false;
                    continue;
                }

                if (key is "cls" && !IsRecognizedClassificationToken(token))
                {
                    diagnostics.Add($"Unknown classification token '{token}'.");
                }
                else if (key is "conf" && !IsRecognizedConfidenceToken(token))
                {
                    diagnostics.Add($"Unknown confidence token '{token}'.");
                }
                else if (key is "p" && !IsRecognizedProbeToken(token))
                {
                    diagnostics.Add($"Unknown probe outcome token '{token}'.");
                }

                safeTokens.Add(token);
            }

            if (safeTokens.Count == 0)
            {
                valid = false;
                continue;
            }

            parsed[key] = safeTokens;
        }

        return new CompactRuntimeSampleParseResult(valid, CompactFormatVersion, parsed, diagnostics);
    }

    private static RuntimeSamplePayload BuildSamplePayload(
        ContainerRuntimeReport report,
        RuntimeSampleOptions options,
        string environmentKind,
        string scenarioName,
        IReadOnlyList<RuntimeSampleSignal> importantSignals)
    {
        var host = report.Host;
        var fingerprint = host.Fingerprint;
        var sampleFingerprint = fingerprint is null
            ? null
            : new RuntimeSampleFingerprint(
                fingerprint.Algorithm,
                fingerprint.Value,
                ShortHash(fingerprint.Value, 8),
                fingerprint.Stability.ToString(),
                fingerprint.IncludedSignalCount,
                fingerprint.ExcludedSensitiveSignalCount);

        return new RuntimeSamplePayload(
            Id: $"crp-sample-{Guid.NewGuid():N}",
            CreatedAt: report.GeneratedAt,
            ScenarioName: scenarioName,
            UserProvidedScenarioName: options.Scenario,
            EnvironmentKind: environmentKind,
            ExpectedClassification: options.Expected,
            ActualClassification: new RuntimeSampleClassification(
                report.Classification.IsContainerized.Value,
                report.Classification.ContainerRuntime.Value,
                report.Classification.RuntimeApi.Value,
                report.Classification.Orchestrator.Value,
                report.Classification.CloudProvider.Value,
                report.Classification.PlatformVendor.Value),
            Confidence: new RuntimeSampleClassificationConfidence(
                report.Classification.IsContainerized.Confidence.ToString(),
                report.Classification.ContainerRuntime.Confidence.ToString(),
                report.Classification.RuntimeApi.Confidence.ToString(),
                report.Classification.Orchestrator.Confidence.ToString(),
                report.Classification.CloudProvider.Confidence.ToString(),
                report.Classification.PlatformVendor.Confidence.ToString()),
            Host: new RuntimeSampleHost(
                new RuntimeSampleContainerImageOs(
                    host.ContainerImageOs.Family.ToString(),
                    host.ContainerImageOs.Id,
                    host.ContainerImageOs.Version ?? host.ContainerImageOs.VersionId,
                    host.ContainerImageOs.PrettyName,
                    NormalizeArchitecture(host.ContainerImageOs.Architecture)),
                new RuntimeSampleVisibleKernel(
                    host.VisibleKernel.Name,
                    host.VisibleKernel.Release,
                    NormalizeKernelRelease(host.VisibleKernel.Release, 48),
                    NormalizeUnknown(host.VisibleKernel.Flavor.ToString()),
                    NormalizeArchitecture(host.VisibleKernel.Architecture)),
                new RuntimeSampleRuntimeReportedHostOs(
                    NormalizeUnknown(host.RuntimeReportedHostOs.Source.ToString()),
                    host.RuntimeReportedHostOs.Name,
                    host.RuntimeReportedHostOs.Version,
                    NormalizeArchitecture(host.RuntimeReportedHostOs.Architecture)),
                new RuntimeSampleHardware(
                    NormalizeArchitecture(host.Hardware.Architecture),
                    NormalizeCpuVendor(host.Hardware.Cpu.Vendor),
                    NormalizeCpuFamily(host.Hardware.Cpu.Family),
                    host.Hardware.Cpu.ModelName,
                    host.Hardware.Cpu.LogicalProcessorCount,
                    host.Hardware.Cpu.VisibleProcessorCount,
                    host.Hardware.Cpu.FlagsHash,
                    host.Hardware.Memory.MemTotalBytes,
                    NormalizeMemoryBucketShort(host.Hardware.Memory.MemTotalBytes),
                    host.Hardware.Memory.CgroupMemoryLimitRaw),
                sampleFingerprint),
            ImportantSignals: importantSignals,
            ProbeOutcomes: new RuntimeSampleProbeOutcomes(
                MapProbeOutcome(report, "marker-files"),
                MapProbeOutcome(report, "environment"),
                MapProbeOutcome(report, "proc-files"),
                MapProbeOutcome(report, "security-sandbox"),
                MapProbeOutcome(report, "runtime-api"),
                MapProbeOutcome(report, "kubernetes"),
                MapProbeOutcome(report, "cloud-metadata")),
            SecurityWarnings: BuildSecurityWarnings(report),
            Redaction: new RuntimeSampleRedaction(
                Mode: options.IncludeSensitive ? "explicit" : "safe",
                FullReportContainsSensitiveValues: options.IncludeSensitive,
                ExcludedFromIssueUrl:
                [
                    "raw mountinfo",
                    "raw cgroup container ids",
                    "hostname",
                    "container id",
                    "cloud instance id",
                    "tokens",
                    "secrets",
                    "raw cpu serial",
                    "raw full metadata documents"
                ]));
    }

    private static CompactSampleData BuildCompactSampleData(
        ContainerRuntimeReport report,
        RuntimeSamplePayload payload,
        IReadOnlyList<RuntimeSampleSignal> importantSignals)
    {
        var host = payload.Host;
        return new CompactSampleData(
            [
                MapContainerized(payload.ActualClassification.IsContainerized),
                MapRuntime(payload.ActualClassification.ContainerRuntime),
                MapRuntimeApi(payload.ActualClassification.RuntimeApi),
                MapOrchestrator(payload.ActualClassification.Orchestrator),
                MapCloud(payload.ActualClassification.CloudProvider),
                MapPlatformVendor(payload.ActualClassification.PlatformVendor, payload.ActualClassification.Orchestrator, payload.ActualClassification.CloudProvider, payload.Host.VisibleKernel.Flavor)
            ],
            [
                $"c{MapConfidenceSuffix(report.Classification.IsContainerized.Confidence)}",
                $"rt{MapConfidenceSuffix(report.Classification.ContainerRuntime.Confidence)}",
                $"api{MapConfidenceSuffix(report.Classification.RuntimeApi.Confidence)}",
                $"orc{MapConfidenceSuffix(report.Classification.Orchestrator.Confidence)}",
                $"cl{MapConfidenceSuffix(report.Classification.CloudProvider.Confidence)}",
                $"pv{MapConfidenceSuffix(report.Classification.PlatformVendor.Confidence)}"
            ],
            new CompactHostSection(
                ShortOsToken(host.ContainerImageOs),
                NormalizeKernelRelease(host.VisibleKernel.Release, 48),
                host.VisibleKernel.Flavor == "Unknown" ? "Unknown" : host.VisibleKernel.Flavor,
                host.VisibleKernel.Architecture == "unk" ? host.ContainerImageOs.Architecture : host.VisibleKernel.Architecture,
                ShortRuntimeHostOs(host.RuntimeReportedHostOs)),
            new CompactHardwareSection(
                host.Hardware.CpuVendor ?? "unk",
                host.Hardware.CpuFamily ?? "unk",
                host.Hardware.LogicalProcessorCount,
                host.Hardware.VisibleProcessorCount,
                host.Hardware.MemoryTotalBucket ?? "unk",
                NormalizeMemoryLimit(host.Hardware.CgroupMemoryLimitRaw, host.Hardware.MemoryTotalBytes),
                host.Hardware.CpuFlagsHash),
            new CompactFingerprintSection(
                host.Fingerprint?.ShortValue ?? "sha256:0",
                host.Fingerprint?.Stability ?? "Unknown",
                host.Fingerprint?.IncludedSignalCount ?? 0,
                host.Fingerprint?.ExcludedSensitiveSignalCount ?? 0),
            [
                $"mk:{payload.ProbeOutcomes.MarkerFiles}",
                $"env:{payload.ProbeOutcomes.Environment}",
                $"proc:{payload.ProbeOutcomes.ProcFiles}",
                $"sbx:{payload.ProbeOutcomes.SecuritySandbox}",
                $"api:{payload.ProbeOutcomes.RuntimeApi}",
                $"k8s:{payload.ProbeOutcomes.Kubernetes}",
                $"meta:{payload.ProbeOutcomes.CloudMetadata}"
            ],
            importantSignals.Select(signal => signal.Tag).Distinct(StringComparer.Ordinal).ToArray(),
            BuildSecurityWarnings(report));
    }

    private static UrlArtifacts RenderUrlArtifacts(
        ContainerRuntimeReport report,
        RuntimeSampleOptions options,
        string scenarioName,
        CompactSampleData compactData,
        RuntimeSamplePayload payload)
    {
        var warnings = new List<string>();
        var currentBodyFormat = string.Equals(options.BodyFormat, "expanded", StringComparison.OrdinalIgnoreCase) ? "expanded" : "compact";
        var renderOptions = new CompactRenderOptions(IncludeHardware: true, KernelReleaseLength: 48, FingerprintLength: 8, SignalMode: SignalReductionMode.All);
        var repository = string.IsNullOrWhiteSpace(options.Repository) ? DefaultRepository : options.Repository;
        var template = string.IsNullOrWhiteSpace(options.IssueTemplate) ? DefaultTemplate : options.IssueTemplate;

        string compactSample;
        string body;
        string url;

        url = BuildUrl(renderOptions, currentBodyFormat);
        if (url.Length <= options.MaxUrlLength)
        {
            return new UrlArtifacts(url, warnings, renderOptions);
        }

        if (currentBodyFormat == "expanded")
        {
            currentBodyFormat = "compact";
            warnings.Add("Expanded issue body was reduced to the compact body to stay within the URL length target.");
            url = BuildUrl(renderOptions, currentBodyFormat);
            if (url.Length <= options.MaxUrlLength)
            {
                return new UrlArtifacts(url, warnings, renderOptions);
            }
        }

        renderOptions = renderOptions with { IncludeHardware = false };
        warnings.Add("Hardware section was removed from the URL sample to stay within the URL length target.");
        url = BuildUrl(renderOptions, currentBodyFormat);
        if (url.Length <= options.MaxUrlLength)
        {
            return new UrlArtifacts(url, warnings, renderOptions);
        }

        renderOptions = renderOptions with { KernelReleaseLength = 24 };
        warnings.Add("Kernel release was shortened in the URL sample.");
        url = BuildUrl(renderOptions, currentBodyFormat);
        if (url.Length <= options.MaxUrlLength)
        {
            return new UrlArtifacts(url, warnings, renderOptions);
        }

        renderOptions = renderOptions with { FingerprintLength = 6 };
        warnings.Add("Fingerprint was shortened in the URL sample.");
        url = BuildUrl(renderOptions, currentBodyFormat);
        if (url.Length <= options.MaxUrlLength)
        {
            return new UrlArtifacts(url, warnings, renderOptions);
        }

        renderOptions = renderOptions with { SignalMode = SignalReductionMode.Priority };
        warnings.Add("Lower-priority signal tags were removed from the URL sample.");
        url = BuildUrl(renderOptions, currentBodyFormat);
        if (url.Length <= options.MaxUrlLength)
        {
            return new UrlArtifacts(url, warnings, renderOptions);
        }

        renderOptions = renderOptions with { SignalMode = SignalReductionMode.Core };
        warnings.Add("URL sample fell back to classification, host, fingerprint, and key signals only.");
        url = BuildUrl(renderOptions, currentBodyFormat);
        if (url.Length <= options.MaxUrlLength)
        {
            return new UrlArtifacts(url, warnings, renderOptions);
        }

        warnings.Add("Issue URL is still longer than the configured target. Use --body-only or manual copy/paste if your browser rejects the URL.");
        return new UrlArtifacts(url, warnings, renderOptions);

        string BuildUrl(CompactRenderOptions candidateOptions, string bodyFormat)
        {
            compactSample = RenderCompactSample(compactData, candidateOptions);
            body = BuildIssueBody(report, compactSample, scenarioName, payload, bodyFormat == "expanded", options.Expected);
            return BuildIssueUrl(repository, template, scenarioName, body);
        }
    }

    private static string BuildIssueBody(ContainerRuntimeReport report, string compactSample, string scenarioName, RuntimeSamplePayload payload, bool expanded, string? expected)
    {
        var sb = new StringBuilder();
        sb.AppendLine("## Runtime Sample");
        sb.AppendLine();
        sb.AppendLine("```text");
        sb.AppendLine(compactSample);
        sb.AppendLine("```");
        sb.AppendLine();
        sb.AppendLine("### Summary");
        sb.AppendLine($"- Scenario: {scenarioName}");
        sb.AppendLine($"- Containerized: {payload.ActualClassification.IsContainerized} ({payload.Confidence.IsContainerized})");
        sb.AppendLine($"- Runtime: {payload.ActualClassification.ContainerRuntime} ({payload.Confidence.ContainerRuntime})");
        sb.AppendLine($"- Runtime API: {payload.ActualClassification.RuntimeApi}");
        sb.AppendLine($"- Orchestrator: {payload.ActualClassification.Orchestrator}");
        sb.AppendLine($"- Cloud: {payload.ActualClassification.CloudProvider}");
        sb.AppendLine($"- Platform Vendor: {payload.ActualClassification.PlatformVendor}");
        sb.AppendLine($"- Kernel Flavor: {payload.Host.VisibleKernel.Flavor}");
        sb.AppendLine($"- Fingerprint: {payload.Host.Fingerprint?.ShortValue ?? "sha256:0"}");
        if (!string.IsNullOrWhiteSpace(expected))
        {
            sb.AppendLine($"- Expected: {expected}");
        }

        if (expanded)
        {
            sb.AppendLine();
            sb.AppendLine("### Host OS / Node Signals");
            sb.AppendLine($"- Container Image OS: {payload.Host.ContainerImageOs.PrettyName ?? payload.Host.ContainerImageOs.Id ?? "Unknown"}");
            sb.AppendLine($"- Visible Kernel: {payload.Host.VisibleKernel.Release ?? "Unknown"}");
            sb.AppendLine($"- Runtime-Reported Host OS: {payload.Host.RuntimeReportedHostOs.Name ?? "Unknown"}");
            sb.AppendLine();
            sb.AppendLine("### Hardware Signals");
            sb.AppendLine($"- CPU Vendor: {payload.Host.Hardware.CpuVendor ?? "Unknown"}");
            sb.AppendLine($"- CPU Family: {payload.Host.Hardware.CpuFamily ?? "Unknown"}");
            sb.AppendLine($"- Visible CPUs: {payload.Host.Hardware.VisibleProcessorCount?.ToString() ?? "Unknown"}");
            sb.AppendLine($"- Memory Bucket: {payload.Host.Hardware.MemoryTotalBucket ?? "Unknown"}");
            sb.AppendLine();
            sb.AppendLine("### Important Signals");
            foreach (var signal in payload.ImportantSignals)
            {
                sb.AppendLine($"- `{signal.Tag}` = {signal.Value}");
            }
        }

        sb.AppendLine();
        sb.AppendLine("### Optional full report");
        sb.AppendLine("If you can share the full redacted report, please attach or paste `my-report.json`.");
        sb.AppendLine();
        sb.AppendLine("Docker:");
        sb.AppendLine("```bash");
        sb.AppendLine("docker run --rm ghcr.io/bobiene/container-runtime-probe:latest json > my-report.json");
        sb.AppendLine("```");
        sb.AppendLine();
        sb.AppendLine("Local tool:");
        sb.AppendLine("```bash");
        sb.AppendLine("container-runtime-probe json > my-report.json");
        sb.AppendLine("```");
        sb.AppendLine();
        sb.AppendLine("### Notes");
        sb.AppendLine("Please add any context that is not visible from inside the container:");
        sb.AppendLine("- Host OS:");
        sb.AppendLine("- Docker/Podman/Kubernetes version:");
        sb.AppendLine("- Cloud/edge platform:");
        sb.AppendLine("- Expected classification:");
        return sb.ToString().TrimEnd();
    }

    private static string BuildIssueUrl(string repository, string template, string scenarioName, string body)
    {
        var title = $"Runtime sample: {scenarioName}";
        return $"https://github.com/{repository}/issues/new?template={Uri.EscapeDataString(template)}&title={Uri.EscapeDataString(title)}&body={Uri.EscapeDataString(body)}";
    }

    private static IReadOnlyList<string> BuildSummaryLines(ContainerRuntimeReport report, string scenarioName, RuntimeSamplePayload payload)
        =>
        [
            $"- Scenario: {scenarioName}",
            $"- ContainerRuntime: {report.Classification.ContainerRuntime.Value} ({report.Classification.ContainerRuntime.Confidence})",
            $"- KernelFlavor: {payload.Host.VisibleKernel.Flavor}",
            $"- PlatformVendor: {report.Classification.PlatformVendor.Value}",
            $"- CloudProvider: {report.Classification.CloudProvider.Value}",
            $"- Fingerprint: {payload.Host.Fingerprint?.ShortValue ?? "sha256:0"}"
        ];

    private static IReadOnlyList<RuntimeSampleSignal> BuildImportantSignals(ContainerRuntimeReport report)
    {
        var evidence = report.Probes.SelectMany(probe => probe.Evidence).ToList();
        var signals = new List<(int priority, RuntimeSampleSignal signal)>();

        void Add(int priority, string key, string value, string tag)
        {
            if (signals.Any(existing => string.Equals(existing.signal.Tag, tag, StringComparison.Ordinal)))
            {
                return;
            }

            signals.Add((priority, new RuntimeSampleSignal(key, value, tag)));
        }

        if (evidence.Any(item => item.Key == "/.dockerenv" && string.Equals(item.Value, bool.TrueString, StringComparison.OrdinalIgnoreCase)))
        {
            Add(1, "marker./.dockerenv", "true", "de");
        }

        if (evidence.Any(item => item.Key == "/run/.containerenv" && string.Equals(item.Value, bool.TrueString, StringComparison.OrdinalIgnoreCase)))
        {
            Add(1, "marker./run/.containerenv", "true", "ce");
        }

        foreach (var pattern in NormalizeCgroupPatterns(evidence))
        {
            Add(1, "cgroup.pattern", pattern, $"cg:{pattern}");
        }

        foreach (var mount in NormalizeMountSignals(evidence))
        {
            Add(mount.StartsWith("mt:", StringComparison.Ordinal) ? 2 : 4, mount.StartsWith("mt:", StringComparison.Ordinal) ? "mount.type" : "mount.hint", mount[(mount.IndexOf(':') + 1)..], mount);
        }

        if (report.Host.VisibleKernel.Flavor != KernelFlavor.Unknown)
        {
            Add(1, "kernel.flavor", report.Host.VisibleKernel.Flavor.ToString(), $"kf:{report.Host.VisibleKernel.Flavor}");
        }

        if (report.Host.VisibleKernel.Flavor == KernelFlavor.WSL2 || (report.Host.VisibleKernel.Release?.Contains("wsl", StringComparison.OrdinalIgnoreCase) ?? false))
        {
            Add(1, "kernel.wsl", "true", "wsl");
        }

        if (evidence.Any(item => item.Key == "env.KUBERNETES_SERVICE_HOST"))
        {
            Add(2, "env.KUBERNETES_SERVICE_HOST", "present", "ke");
        }

        if (evidence.Any(item => item.Key == "serviceaccount.token"))
        {
            Add(2, "serviceaccount.token", "present", "ksa");
        }

        if (evidence.Any(item => item.Key == "socket.present" && item.Value?.Contains("docker", StringComparison.OrdinalIgnoreCase) == true))
        {
            Add(2, "socket.present", "docker", "dockersock");
        }

        if (evidence.Any(item => item.Key == "socket.present" && item.Value?.Contains("podman", StringComparison.OrdinalIgnoreCase) == true))
        {
            Add(2, "socket.present", "podman", "podmansock");
        }

        if (evidence.Any(item => item.Key == "azure.imds.outcome" && item.Value == ProbeOutcome.Success.ToString()))
        {
            Add(2, "metadata.azure", "Success", "md:az");
        }

        if (evidence.Any(item => item.Key == "aws.imds.identity.outcome" && item.Value == ProbeOutcome.Success.ToString()))
        {
            Add(2, "metadata.aws", "Success", "md:aws");
        }

        if (evidence.Any(item => item.Key == "gcp.metadata.outcome" && item.Value == ProbeOutcome.Success.ToString()))
        {
            Add(2, "metadata.gcp", "Success", "md:gcp");
        }

        foreach (var ns in evidence.Where(item => item.Key.StartsWith("ns.", StringComparison.Ordinal) && item.Value != "unavailable"))
        {
            var hint = ns.Key.Split('.').Last();
            Add(4, ns.Key, "present", $"ns:{hint}ns");
        }

        Add(1, "runtime-api.outcome", NormalizeRuntimeApiSignal(report.Classification.RuntimeApi.Value), NormalizeRuntimeApiSignal(report.Classification.RuntimeApi.Value));

        return signals.OrderBy(item => item.priority).ThenBy(item => item.signal.Tag, StringComparer.Ordinal).Select(item => item.signal).ToArray();
    }

    private static IReadOnlyList<string> NormalizeCgroupPatterns(IReadOnlyList<EvidenceItem> evidence)
    {
        var patterns = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in evidence.Where(item => item.Key.EndsWith(":signal", StringComparison.Ordinal) && item.Key.Contains("cgroup", StringComparison.OrdinalIgnoreCase)))
        {
            var value = item.Value ?? string.Empty;
            if (value.Contains("/docker/", StringComparison.OrdinalIgnoreCase)) patterns.Add("docker");
            else if (value.Contains("/kubepods/", StringComparison.OrdinalIgnoreCase)) patterns.Add("kubepods");
            else if (value.Contains("containerd", StringComparison.OrdinalIgnoreCase)) patterns.Add("containerd");
            else if (value.Contains("podman", StringComparison.OrdinalIgnoreCase) || value.Contains("libpod", StringComparison.OrdinalIgnoreCase)) patterns.Add("podman");
            else if (value.Contains("ecs", StringComparison.OrdinalIgnoreCase)) patterns.Add("ecs");
            else patterns.Add("unknown");
        }

        return patterns.ToArray();
    }

    private static IReadOnlyList<string> NormalizeMountSignals(IReadOnlyList<EvidenceItem> evidence)
    {
        var tags = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in evidence.Where(item => item.Key.EndsWith(":signal", StringComparison.Ordinal) && item.Key.Contains("mountinfo", StringComparison.OrdinalIgnoreCase)))
        {
            switch (item.Value)
            {
                case "overlay":
                    tags.Add("mt:overlay");
                    break;
                case "kubelet":
                    tags.Add("mi:kubelet");
                    break;
                case "containerd":
                    tags.Add("mi:containerd");
                    break;
                case "podman":
                    tags.Add("mi:podman");
                    break;
                case "kubernetes-serviceaccount":
                    tags.Add("mi:ksa");
                    break;
            }
        }

        return tags.ToArray();
    }

    private static IReadOnlyList<string> BuildSecurityWarnings(ContainerRuntimeReport report)
    {
        var warnings = new List<string>();
        if (report.SecurityWarnings.Any(warning => string.Equals(warning.Code, "DOCKER_SOCKET_MOUNTED", StringComparison.Ordinal)))
        {
            warnings.Add("DS");
        }

        if (warnings.Count == 0)
        {
            warnings.Add("none");
        }

        return warnings;
    }

    private static IReadOnlyList<string> BuildHostTokens(CompactHostSection host, CompactRenderOptions options)
    {
        var tokens = new List<string>
        {
            $"os:{AsciiToken(host.Os)}",
            $"ker:{AsciiToken(NormalizeKernelRelease(host.KernelRelease, options.KernelReleaseLength))}",
            $"kf:{AsciiToken(host.KernelFlavor)}",
            $"arch:{AsciiToken(host.Architecture)}",
            $"rhos:{AsciiToken(host.RuntimeHostOs)}"
        };
        return tokens;
    }

    private static IReadOnlyList<string> BuildHardwareTokens(CompactHardwareSection hardware, CompactRenderOptions options)
    {
        if (!options.IncludeHardware)
        {
            return [];
        }

        var tokens = new List<string>();
        Add(tokens, "cv", hardware.CpuVendor);
        Add(tokens, "cf", hardware.CpuFamily);
        Add(tokens, "lc", hardware.LogicalCpus?.ToString(CultureInfo.InvariantCulture));
        Add(tokens, "vc", hardware.VisibleCpus?.ToString(CultureInfo.InvariantCulture));
        Add(tokens, "mem", hardware.MemoryBucket);
        Add(tokens, "lim", hardware.MemoryLimit);
        Add(tokens, "flg", ShortHash(hardware.FlagsHash, 8));
        return tokens;

        static void Add(ICollection<string> tokens, string key, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value) && value != "unk")
            {
                tokens.Add($"{key}:{AsciiToken(value)}");
            }
        }
    }

    private static IReadOnlyList<string> BuildFingerprintTokens(CompactFingerprintSection fingerprint, CompactRenderOptions options)
        =>
        [
            AsciiToken(ShortHash(fingerprint.Value, options.FingerprintLength)),
            $"st:{AsciiToken(fingerprint.Stability)}",
            $"n:{fingerprint.IncludedSignals.ToString(CultureInfo.InvariantCulture)}",
            $"x:{fingerprint.ExcludedSignals.ToString(CultureInfo.InvariantCulture)}"
        ];

    private static IReadOnlyList<string> BuildSignalTokens(IReadOnlyList<string> signals, CompactRenderOptions options)
    {
        IEnumerable<string> filtered = options.SignalMode switch
        {
            SignalReductionMode.All => signals,
            SignalReductionMode.Priority => signals.Where(signal => signal is "de" or "ce" or "wsl" or "ke" or "ksa" or "dockersock" or "podmansock" || signal.StartsWith("cg:", StringComparison.Ordinal) || signal.StartsWith("mt:", StringComparison.Ordinal) || signal.StartsWith("kf:", StringComparison.Ordinal) || signal.StartsWith("api:", StringComparison.Ordinal) || signal.StartsWith("md:", StringComparison.Ordinal)),
            SignalReductionMode.Core => signals.Where(signal => signal is "de" or "ce" or "wsl" || signal.StartsWith("cg:", StringComparison.Ordinal) || signal.StartsWith("kf:", StringComparison.Ordinal) || signal.StartsWith("api:", StringComparison.Ordinal)).Take(6),
            _ => signals
        };

        return filtered.Select(AsciiToken).Distinct(StringComparer.Ordinal).ToArray();
    }

    private static string InferEnvironmentKind(ContainerRuntimeReport report)
    {
        if (report.Classification.PlatformVendor.Value == "Siemens Industrial Edge") return "SiemensIndustrialEdge";
        if (report.Classification.Orchestrator.Value == "Azure Container Apps") return "AzureContainerApps";
        if (report.Classification.Orchestrator.Value == "AWS ECS") return "Ecs";
        if (report.Classification.Orchestrator.Value == "Cloud Run") return "CloudRun";
        if (report.Classification.Orchestrator.Value == "Kubernetes") return "Kubernetes";
        if (report.Classification.ContainerRuntime.Value == "Podman") return "Podman";
        if (report.Classification.ContainerRuntime.Value == "Docker" && report.Host.VisibleKernel.Flavor == KernelFlavor.WSL2) return "DockerDesktopWsl2";
        if (report.Classification.ContainerRuntime.Value == "Docker") return "DockerLinux";
        return "Unknown";
    }

    private static string InferScenarioName(ContainerRuntimeReport report)
    {
        if (report.Classification.PlatformVendor.Value == "Siemens Industrial Edge") return "siemens-industrial-edge";
        if (report.Classification.Orchestrator.Value == "Azure Container Apps") return "azure-container-apps";
        if (report.Classification.Orchestrator.Value == "Cloud Run") return "google-cloud-run";
        if (report.Classification.Orchestrator.Value == "AWS ECS")
        {
            var hasFargate = report.Probes.SelectMany(probe => probe.Evidence)
                .Any(item => item.Key is "env.AWS_EXECUTION_ENV" or "AWS_EXECUTION_ENV" && item.Value?.Contains("fargate", StringComparison.OrdinalIgnoreCase) == true);
            return hasFargate ? "aws-ecs-fargate" : "aws-ecs";
        }

        if (report.Classification.Orchestrator.Value == "Kubernetes")
        {
            return report.Classification.ContainerRuntime.Value == "containerd"
                ? "kubernetes-containerd"
                : "kubernetes";
        }

        if (report.Classification.ContainerRuntime.Value == "Docker" && report.Host.VisibleKernel.Flavor == KernelFlavor.WSL2) return "docker-wsl2";
        if (report.Classification.ContainerRuntime.Value == "Docker" && report.Host.VisibleKernel.Flavor == KernelFlavor.DockerDesktop) return "docker-desktop";
        if (report.Classification.ContainerRuntime.Value == "Docker" && report.Classification.CloudProvider.Value == "Azure") return "docker-azure";
        if (report.Classification.ContainerRuntime.Value == "Podman") return "podman";
        return "unknown-runtime";
    }

    private static string NormalizeScenario(string value)
        => string.Join('-', value.Trim().ToLowerInvariant().Split([' ', '_'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    private static string NormalizeRuntimeApiSignal(string runtimeApi)
        => runtimeApi switch
        {
            "DockerEngineApi" => "api:docker",
            "PodmanLibpodApi" => "api:podman",
            _ => "api:0"
        };

    private static string MapContainerized(string value)
        => value switch
        {
            "True" => "c1",
            "False" => "c0",
            _ => "c?"
        };

    private static string MapRuntime(string value)
        => value switch
        {
            "Docker" => "rtD",
            "Podman" => "rtP",
            "containerd" => "rtC",
            "CRI-O" => "rtO",
            _ => "rt0"
        };

    private static string MapRuntimeApi(string value)
        => value switch
        {
            "DockerEngineApi" => "apiD",
            "PodmanLibpodApi" => "apiP",
            "KubernetesApi" => "apiC",
            _ => "api0"
        };

    private static string MapOrchestrator(string value)
        => value switch
        {
            "Kubernetes" => "orcK",
            "AWS ECS" => "orcE",
            "Azure Container Apps" => "orcA",
            "Cloud Run" => "orcR",
            _ => "orc0"
        };

    private static string MapCloud(string value)
        => value switch
        {
            "Azure" => "clA",
            "AWS" => "clW",
            "GoogleCloud" => "clG",
            _ => "cl0"
        };

    private static string MapPlatformVendor(string vendor, string orchestrator, string cloud, string kernelFlavor)
    {
        if (vendor == "Siemens Industrial Edge") return "pvSIE";
        if (kernelFlavor == "DockerDesktop") return "pvDD";
        if (orchestrator == "Kubernetes" && cloud == "Azure") return "pvAKS";
        if (orchestrator == "Kubernetes" && cloud == "AWS") return "pvEKS";
        if (orchestrator == "Kubernetes" && cloud == "GoogleCloud") return "pvGKE";
        return "pv0";
    }

    private static char MapConfidenceSuffix(Confidence confidence)
        => confidence switch
        {
            Confidence.High => 'H',
            Confidence.Medium => 'M',
            Confidence.Low => 'L',
            _ => 'U'
        };

    private static string ShortOsToken(RuntimeSampleContainerImageOs os)
    {
        var family = os.Family.ToLowerInvariant();
        var digits = Regex.Match(os.Version ?? string.Empty, @"\d+(?:\.\d+)?").Value.Replace(".", string.Empty, StringComparison.Ordinal);
        return family switch
        {
            "debian" => $"deb{TrimDigits(digits, 2, "0")}",
            "ubuntu" => $"ubu{TrimDigits(digits, 2, "0")}",
            "alpine" => $"alp{TrimDigits(digits, 3, "0")}",
            "mariner" => $"mariner{TrimDigits(digits, 1, "0")}",
            "azurelinux" => $"mariner{TrimDigits(digits, 1, "0")}",
            "windowsserver" or "windowsservercore" or "windowsnanoserver" => $"win{TrimDigits(digits, 4, "0")}",
            _ => string.IsNullOrWhiteSpace(digits) ? (os.Id ?? "unk") : $"{(os.Id ?? family)[..Math.Min(3, (os.Id ?? family).Length)]}{digits}"
        };

        static string TrimDigits(string digits, int maxLength, string fallback)
        {
            if (string.IsNullOrWhiteSpace(digits)) return fallback;
            return digits.Length <= maxLength ? digits : digits[..maxLength];
        }
    }

    private static string ShortRuntimeHostOs(RuntimeSampleRuntimeReportedHostOs hostOs)
    {
        if (string.IsNullOrWhiteSpace(hostOs.Name))
        {
            return "0";
        }

        var lower = hostOs.Name.ToLowerInvariant();
        if (lower.Contains("ubuntu", StringComparison.Ordinal)) return $"ubu{Regex.Match(lower, @"\d+").Value}";
        if (lower.Contains("debian", StringComparison.Ordinal)) return $"deb{Regex.Match(lower, @"\d+").Value}";
        if (lower.Contains("windows", StringComparison.Ordinal)) return $"win{Regex.Match(lower, @"\d+").Value}";
        return AsciiToken(lower.Length > 12 ? lower[..12] : lower);
    }

    private static string NormalizeKernelRelease(string? release, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(release))
        {
            return "unk";
        }

        var normalized = release.Trim().ToLowerInvariant()
            .Replace("microsoft-standard", "ms", StringComparison.Ordinal)
            .Replace("standard", "std", StringComparison.Ordinal)
            .Replace("+", "-", StringComparison.Ordinal);
        normalized = Regex.Replace(normalized, "[^a-z0-9._-]", "-");
        normalized = Regex.Replace(normalized, "-+", "-");
        return normalized.Length <= maxLength ? normalized : normalized[..maxLength].Trim('-');
    }

    private static string NormalizeArchitecture(ArchitectureKind architecture)
        => architecture switch
        {
            ArchitectureKind.X64 => "x64",
            ArchitectureKind.X86 => "x86",
            ArchitectureKind.Arm64 => "arm64",
            ArchitectureKind.Arm => "arm",
            _ => "unk"
        };

    private static string NormalizeCpuVendor(string? vendor)
    {
        if (string.IsNullOrWhiteSpace(vendor)) return "unk";
        var lower = vendor.ToLowerInvariant();
        if (lower.Contains("intel", StringComparison.Ordinal)) return "Intel";
        if (lower.Contains("amd", StringComparison.Ordinal)) return "AMD";
        if (lower.Contains("arm", StringComparison.Ordinal)) return "ARM";
        return AsciiToken(vendor);
    }

    private static string NormalizeCpuFamily(string? family)
        => string.IsNullOrWhiteSpace(family) ? "unk" : AsciiToken(family.Length > 16 ? family[..16] : family);

    private static string NormalizeMemoryBucketShort(long? bytes)
    {
        if (bytes is null or <= 0)
        {
            return "unk";
        }

        var gib = bytes.Value / (1024d * 1024d * 1024d);
        if (gib >= 1)
        {
            return $"{Math.Max(1, (int)Math.Round(gib, MidpointRounding.AwayFromZero))}G";
        }

        var mib = bytes.Value / (1024d * 1024d);
        return $"{Math.Max(1, (int)Math.Round(mib, MidpointRounding.AwayFromZero))}M";
    }

    private static string NormalizeMemoryLimit(string? rawLimit, long? fallbackBytes)
    {
        if (string.IsNullOrWhiteSpace(rawLimit) || string.Equals(rawLimit, "max", StringComparison.OrdinalIgnoreCase))
        {
            return "max";
        }

        if (long.TryParse(rawLimit, CultureInfo.InvariantCulture, out var parsed))
        {
            if (parsed >= long.MaxValue / 4)
            {
                return "max";
            }

            return NormalizeMemoryBucketShort(parsed);
        }

        return fallbackBytes.HasValue ? NormalizeMemoryBucketShort(fallbackBytes) : "max";
    }

    private static string ShortHash(string? hash, int hexLength)
    {
        if (string.IsNullOrWhiteSpace(hash))
        {
            return "sha256:0";
        }

        var prefix = hash.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) ? "sha256:" : string.Empty;
        var value = prefix.Length == 0 ? hash : hash[prefix.Length..];
        var truncated = value.Length <= hexLength ? value : value[..hexLength];
        return $"{prefix}{AsciiToken(truncated)}";
    }

    private static string NormalizeUnknown(string value)
        => string.Equals(value, "Unknown", StringComparison.OrdinalIgnoreCase) ? "Unknown" : value;

    private static string MapProbeOutcome(ContainerRuntimeReport report, string probeId)
    {
        var outcome = report.Probes.FirstOrDefault(probe => string.Equals(probe.ProbeId, probeId, StringComparison.Ordinal))?.Outcome;
        return outcome switch
        {
            ProbeOutcome.Success => "S",
            ProbeOutcome.Unavailable => "U",
            ProbeOutcome.NotSupported => "N",
            ProbeOutcome.AccessDenied => "F",
            ProbeOutcome.Timeout => "E",
            ProbeOutcome.Error => "E",
            _ => "N"
        };
    }

    private static string GetToolVersion()
    {
        var assembly = typeof(ContainerRuntimeProbeEngine).Assembly;
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        return string.IsNullOrWhiteSpace(informational) ? assembly.GetName().Version?.ToString() ?? "0.0.0" : informational;
    }

    private static bool IsRecognizedClassificationToken(string token)
        => token.StartsWith("c", StringComparison.Ordinal)
            || token.StartsWith("rt", StringComparison.Ordinal)
            || token.StartsWith("api", StringComparison.Ordinal)
            || token.StartsWith("orc", StringComparison.Ordinal)
            || token.StartsWith("cl", StringComparison.Ordinal)
            || token.StartsWith("pv", StringComparison.Ordinal);

    private static bool IsRecognizedConfidenceToken(string token)
        => Regex.IsMatch(token, "^(c|rt|api|orc|cl|pv)[HMLUN]$");

    private static bool IsRecognizedProbeToken(string token)
        => Regex.IsMatch(token, "^(mk|env|proc|sbx|api|k8s|meta):[SUFEPN]$");

    private static string AsciiToken(string value)
    {
        var ascii = new string(value.Where(ch => ch <= 127).ToArray()).Trim();
        if (string.IsNullOrWhiteSpace(ascii)) return "unk";
        ascii = Regex.Replace(ascii, "[^A-Za-z0-9._:-]", "-");
        ascii = Regex.Replace(ascii, "-+", "-");
        return ascii.Trim('-');
    }

    internal sealed record CompactRuntimeSampleParseResult(bool IsValid, string Version, IReadOnlyDictionary<string, IReadOnlyList<string>> Sections, IReadOnlyList<string> Diagnostics);
    internal sealed record CompactSampleData(
        IReadOnlyList<string> Classification,
        IReadOnlyList<string> Confidence,
        CompactHostSection Host,
        CompactHardwareSection Hardware,
        CompactFingerprintSection Fingerprint,
        IReadOnlyList<string> ProbeOutcomes,
        IReadOnlyList<string> Signals,
        IReadOnlyList<string> SecurityWarnings);
    internal sealed record CompactHostSection(string Os, string KernelRelease, string KernelFlavor, string Architecture, string RuntimeHostOs);
    internal sealed record CompactHardwareSection(string CpuVendor, string CpuFamily, int? LogicalCpus, int? VisibleCpus, string MemoryBucket, string MemoryLimit, string? FlagsHash);
    internal sealed record CompactFingerprintSection(string Value, string Stability, int IncludedSignals, int ExcludedSignals);
    internal sealed record UrlArtifacts(string Url, IReadOnlyList<string> Warnings, CompactRenderOptions RenderOptions);
    internal sealed record CompactRenderOptions(bool IncludeHardware, int KernelReleaseLength, int FingerprintLength, SignalReductionMode SignalMode);
    internal enum SignalReductionMode { All, Priority, Core }
}
