namespace ContainerRuntimeProbe.Internal;

public static class Parsing
{
    public static Dictionary<string, string> ParseKeyValueLines(IEnumerable<string> lines, char sep = '=')
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines)
        {
            var idx = line.IndexOf(sep);
            if (idx <= 0) continue;
            dict[line[..idx].Trim()] = line[(idx + 1)..].Trim().Trim('"');
        }

        return dict;
    }

    public static IEnumerable<string> ParseResolvSearchDomains(string text)
        => text.Split('\n').Where(l => l.TrimStart().StartsWith("search ", StringComparison.OrdinalIgnoreCase))
            .SelectMany(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1));

    public static IEnumerable<string> ParseDefaultRoutes(string routeText)
    {
        foreach (var line in routeText.Split('\n').Skip(1))
        {
            var cols = line.Split('\t', StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length > 2 && cols[1] == "00000000")
            {
                yield return cols[0];
            }
        }
    }

    public static IEnumerable<string> ParseMountInfoSignals(string text)
    {
        var signals = new[] { "overlay", "kubelet", "containerd", "podman", "/run/secrets/kubernetes.io" };
        return text.Split('\n').Where(l => signals.Any(s => l.Contains(s, StringComparison.OrdinalIgnoreCase))).Take(30);
    }
}
