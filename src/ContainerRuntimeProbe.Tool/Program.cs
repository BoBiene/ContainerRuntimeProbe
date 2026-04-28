using ContainerRuntimeProbe;
using ContainerRuntimeProbe.Rendering;

return await MainAsync(args);

static async Task<int> MainAsync(string[] args)
{
    var format = "text";
    var includeSensitive = false;
    var timeout = TimeSpan.FromSeconds(2);
    var output = string.Empty;
    IReadOnlySet<string>? probes = null;
    var listProbes = false;

    try
    {
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--help":
                case "-h":
                    PrintHelp();
                    return 0;
                case "--format": format = args[++i]; break;
                case "--include-sensitive": includeSensitive = bool.Parse(args[++i]); break;
                case "--timeout": timeout = TimeSpan.Parse(args[++i]); break;
                case "--probe": probes = args[++i].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.OrdinalIgnoreCase); break;
                case "--output": output = args[++i]; break;
                case "--list-probes": listProbes = true; break;
                default:
                    Console.Error.WriteLine($"Invalid argument: {args[i]}");
                    PrintHelp();
                    return 2;
            }
        }

        var engine = new ContainerRuntimeProbeEngine();
        if (listProbes)
        {
            foreach (var id in engine.ProbeIds) Console.WriteLine(id);
            return 0;
        }

        var report = await engine.RunAsync(timeout, includeSensitive, probes).ConfigureAwait(false);
        var rendered = format.ToLowerInvariant() switch
        {
            "json" => ReportRenderer.ToJson(report),
            "markdown" => ReportRenderer.ToMarkdown(report),
            "text" => ReportRenderer.ToText(report),
            _ => null
        };

        if (rendered is null)
        {
            Console.Error.WriteLine($"--format must be one of: json|markdown|text (got: {format})");
            return 2;
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

static void PrintHelp()
{
    Console.WriteLine("container-runtime-probe [options]");
    Console.WriteLine("  --help                    Show help");
    Console.WriteLine("  --format json|markdown|text");
    Console.WriteLine("  --output <path>");
    Console.WriteLine("  --timeout <timespan>      e.g. 00:00:02");
    Console.WriteLine("  --include-sensitive <bool>");
    Console.WriteLine("  --probe <id1,id2>");
    Console.WriteLine("  --list-probes");
}
