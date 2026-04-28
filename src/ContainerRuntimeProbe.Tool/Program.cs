using ContainerRuntimeProbe;
using ContainerRuntimeProbe.Rendering;

var format = "text";
var includeSensitive = false;
var timeout = TimeSpan.FromSeconds(2);
var output = string.Empty;
IReadOnlySet<string>? probes = null;

for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--format":
            format = args[++i];
            break;
        case "--include-sensitive":
            includeSensitive = bool.Parse(args[++i]);
            break;
        case "--timeout":
            timeout = TimeSpan.Parse(args[++i]);
            break;
        case "--probe":
            probes = args[++i].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.OrdinalIgnoreCase);
            break;
        case "--output":
            output = args[++i];
            break;
    }
}

var engine = new RuntimeProbeEngine();
var report = await engine.RunAsync(timeout, includeSensitive, probes);
var rendered = format.ToLowerInvariant() switch
{
    "json" => ReportRenderer.ToJson(report),
    "markdown" => ReportRenderer.ToMarkdown(report),
    _ => ReportRenderer.ToText(report)
};

if (string.IsNullOrWhiteSpace(output))
{
    Console.WriteLine(rendered);
}
else
{
    await File.WriteAllTextAsync(output, rendered);
    Console.WriteLine($"Report written to {output}");
}
