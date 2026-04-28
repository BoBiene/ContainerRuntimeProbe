using ContainerRuntimeProbe;
using ContainerRuntimeProbe.Model;
using ContainerRuntimeProbe.Rendering;

return await MainAsync(args);

static async Task<int> MainAsync(string[] args)
{
    var command = DetectCommand(args);
    var reportFormat = command switch
    {
        "json" or "markdown" or "text" => command,
        _ => "text"
    };
    var sampleFormat = "compact";
    var includeSensitive = false;
    var timeout = TimeSpan.FromSeconds(2);
    var output = string.Empty;
    var fullReport = string.Empty;
    IReadOnlySet<string>? probes = null;
    var listProbes = false;
    var fingerprintMode = FingerprintMode.Safe;
    var repo = "BoBiene/ContainerRuntimeProbe";
    var scenario = string.Empty;
    var expected = string.Empty;
    var bodyFormat = "compact";
    var urlOnly = false;
    var bodyOnly = false;
    var sampleOnly = false;
    var issueTemplate = "runtime-sample.yml";
    var maxUrlLength = 2000;

    try
    {
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (IsCommandToken(arg))
            {
                continue;
            }

            switch (arg)
            {
                case "--help":
                case "-h":
                    PrintHelp();
                    return 0;
                case "--sample":
                    command = "sample";
                    break;
                case "--format":
                    var formatValue = GetRequiredValue(args, ref i, "--format");
                    if (string.Equals(command, "sample", StringComparison.OrdinalIgnoreCase)) sampleFormat = formatValue;
                    else reportFormat = formatValue;
                    break;
                case "--body-format": bodyFormat = GetRequiredValue(args, ref i, "--body-format"); break;
                case "--repo": repo = GetRequiredValue(args, ref i, "--repo"); break;
                case "--scenario": scenario = GetRequiredValue(args, ref i, "--scenario"); break;
                case "--expected": expected = GetRequiredValue(args, ref i, "--expected"); break;
                case "--issue-template": issueTemplate = GetRequiredValue(args, ref i, "--issue-template"); break;
                case "--max-url-length": maxUrlLength = int.Parse(GetRequiredValue(args, ref i, "--max-url-length")); break;
                case "--url-only": urlOnly = true; break;
                case "--body-only": bodyOnly = true; break;
                case "--sample-only": sampleOnly = true; break;
                case "--full-report": fullReport = GetRequiredValue(args, ref i, "--full-report"); break;
                case "--include-sensitive": includeSensitive = bool.Parse(GetRequiredValue(args, ref i, "--include-sensitive")); break;
                case "--timeout": timeout = TimeSpan.Parse(GetRequiredValue(args, ref i, "--timeout")); break;
                case "--probe": probes = GetRequiredValue(args, ref i, "--probe").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.OrdinalIgnoreCase); break;
                case "--output": output = GetRequiredValue(args, ref i, "--output"); break;
                case "--list-probes": listProbes = true; break;
                case "--fingerprint": fingerprintMode = Enum.Parse<FingerprintMode>(GetRequiredValue(args, ref i, "--fingerprint"), ignoreCase: true); break;
                default:
                    Console.Error.WriteLine($"Invalid argument: {arg}");
                    PrintHelp();
                    return 2;
            }
        }

        // Convenience flags for sample artifacts should work without requiring an explicit "sample" command.
        if (urlOnly || bodyOnly || sampleOnly)
        {
            command = "sample";
        }

        if (maxUrlLength < 256)
        {
            throw new ArgumentException($"--max-url-length must be at least 256, but got {maxUrlLength}.");
        }

        var engine = new ContainerRuntimeProbeEngine();
        if (listProbes)
        {
            foreach (var id in engine.ProbeIds) Console.WriteLine(id);
            return 0;
        }

        var report = await engine.RunAsync(timeout, includeSensitive, probes, fingerprintMode).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(fullReport))
        {
            await File.WriteAllTextAsync(fullReport, ReportRenderer.ToJson(report)).ConfigureAwait(false);
        }

        string? rendered;
        if (string.Equals(command, "sample", StringComparison.OrdinalIgnoreCase))
        {
            var artifacts = RuntimeSampleRenderer.Build(
                report,
                new RuntimeSampleOptions(
                    Repository: repo,
                    Scenario: string.IsNullOrWhiteSpace(scenario) ? null : scenario,
                    Expected: string.IsNullOrWhiteSpace(expected) ? null : expected,
                    Format: sampleFormat,
                    BodyFormat: bodyFormat,
                    IssueTemplate: issueTemplate,
                    MaxUrlLength: maxUrlLength,
                    IncludeSensitive: includeSensitive));

            rendered = urlOnly
                ? artifacts.PrefillUrl
                : bodyOnly
                    ? RuntimeSampleRenderer.ToMarkdown(artifacts, bodyFormat)
                    : sampleOnly
                        ? artifacts.CompactSample
                        : sampleFormat.ToLowerInvariant() switch
                        {
                            "compact" => RuntimeSampleRenderer.ToConsoleText(artifacts),
                            "json" => RuntimeSampleRenderer.ToJson(artifacts),
                            "markdown" => RuntimeSampleRenderer.ToMarkdown(artifacts, bodyFormat),
                            _ => null
                        };

            if (rendered is null)
            {
                Console.Error.WriteLine($"sample --format must be one of: compact|json|markdown (got: {sampleFormat})");
                return 2;
            }
        }
        else
        {
            rendered = reportFormat.ToLowerInvariant() switch
            {
                "json" => ReportRenderer.ToJson(report),
                "markdown" => ReportRenderer.ToMarkdown(report),
                "text" => ReportRenderer.ToText(report),
                _ => null
            };

            if (rendered is null)
            {
                Console.Error.WriteLine($"--format must be one of: json|markdown|text (got: {reportFormat})");
                return 2;
            }
        }

        if (string.IsNullOrWhiteSpace(output)) Console.WriteLine(rendered);
        else await File.WriteAllTextAsync(output, rendered).ConfigureAwait(false);

        return 0;
    }
    catch (ArgumentException ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 2;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex);
        return 1;
    }
}

static string GetRequiredValue(IReadOnlyList<string> args, ref int index, string option)
{
    if (++index >= args.Count)
    {
        throw new ArgumentException($"Missing value for {option}.");
    }

    return args[index];
}

static string DetectCommand(IReadOnlyList<string> args)
{
    foreach (var arg in args)
    {
        if (string.Equals(arg, "--sample", StringComparison.OrdinalIgnoreCase))
        {
            return "sample";
        }

        if (arg.StartsWith("-", StringComparison.Ordinal))
        {
            continue;
        }

        if (string.Equals(arg, "sample", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "json", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "markdown", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "text", StringComparison.OrdinalIgnoreCase))
        {
            return arg.ToLowerInvariant();
        }

        break;
    }

    return "report";
}

static bool IsCommandToken(string arg)
    => string.Equals(arg, "sample", StringComparison.OrdinalIgnoreCase)
       || string.Equals(arg, "json", StringComparison.OrdinalIgnoreCase)
       || string.Equals(arg, "markdown", StringComparison.OrdinalIgnoreCase)
       || string.Equals(arg, "text", StringComparison.OrdinalIgnoreCase);

static void PrintHelp()
{
    Console.WriteLine("container-runtime-probe [sample|json|markdown|text] [options]");
    Console.WriteLine("  sample                    Generate a dense runtime sample and GitHub issue URL");
    Console.WriteLine("  json|markdown|text        Report output aliases for --format json|markdown|text");
    Console.WriteLine("  --sample                  Alias for the sample command");
    Console.WriteLine("  --help                    Show help");
    Console.WriteLine("  --format json|markdown|text               Report format");
    Console.WriteLine("  --format compact|json|markdown            Sample format when using sample");
    Console.WriteLine("  --output <path>");
    Console.WriteLine("  --timeout <timespan>      e.g. 00:00:02");
    Console.WriteLine("  --include-sensitive <bool>");
    Console.WriteLine("  --probe <id1,id2>");
    Console.WriteLine("  --list-probes");
    Console.WriteLine("  --fingerprint none|safe|extended");
    Console.WriteLine("  --repo OWNER/REPO         Optional sample issue target (default BoBiene/ContainerRuntimeProbe)");
    Console.WriteLine("  --scenario <name>");
    Console.WriteLine("  --expected <text>");
    Console.WriteLine("  --body-format compact|expanded");
    Console.WriteLine("  --url-only                Print only the sample prefill URL (implies sample)");
    Console.WriteLine("  --body-only               Print only the sample issue body (implies sample)");
    Console.WriteLine("  --sample-only             Print only the compact sample string (implies sample)");
    Console.WriteLine("  --full-report <path>");
    Console.WriteLine("  --issue-template <name>");
    Console.WriteLine("  --max-url-length <int>");
}
