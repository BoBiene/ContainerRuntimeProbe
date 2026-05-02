using System.Text.RegularExpressions;

namespace ContainerRuntimeProbe.Internal;

internal static class Parsing
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
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Contains("overlay", StringComparison.OrdinalIgnoreCase)) results.Add("overlay");
            if (line.Contains("kubelet", StringComparison.OrdinalIgnoreCase)) results.Add("kubelet");
            if (line.Contains("containerd", StringComparison.OrdinalIgnoreCase)) results.Add("containerd");
            if (line.Contains("podman", StringComparison.OrdinalIgnoreCase)) results.Add("podman");
            if (line.Contains("/run/secrets/kubernetes.io", StringComparison.OrdinalIgnoreCase)) results.Add("kubernetes-serviceaccount");
        }

        return results.Take(30);
    }

    /// <summary>
    /// Parses cgroup file (v1 or v2) and returns recognizable container signals such as
    /// docker container IDs, kubepods paths, and Podman container markers.
    /// </summary>
    public static IEnumerable<string> ParseCgroupSignals(string text)
    {
        // cgroup v2: single line "0::/<path>"
        // cgroup v1: multiple lines like "12:memory:/docker/<id>" or "1:name=systemd:/kubepods/..."
        var containerSignals = new[] { "/docker/", "/kubepods/", "kubepods.slice", "/lxc/", "podman", "libpod", "/containerd/", "/actions_job/" };
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Take(50))
        {
            if (containerSignals.Any(s => line.Contains(s, StringComparison.OrdinalIgnoreCase)))
                yield return line.Trim();
        }
    }

    public static (string? PodUid, string? ContainerToken) ExtractKubernetesWorkloadIdentifiers(string cgroupSignal)
    {
        if (string.IsNullOrWhiteSpace(cgroupSignal) || !cgroupSignal.Contains("kubepods", StringComparison.OrdinalIgnoreCase))
        {
            return (null, null);
        }

        var podUid = ExtractPodUid(cgroupSignal);
        var containerToken = ExtractContainerToken(cgroupSignal, podUid);
        return (podUid, containerToken);
    }

    private static string? ExtractPodUid(string cgroupSignal)
    {
        var matches = new[]
        {
            Regex.Match(cgroupSignal, @"pod(?<uid>[0-9a-fA-F]{8}(?:[_-][0-9a-fA-F]{4}){3}[_-][0-9a-fA-F]{12})", RegexOptions.IgnoreCase),
            Regex.Match(cgroupSignal, @"/pod(?<uid>[0-9a-fA-F]{32,64})(?:/|$)", RegexOptions.IgnoreCase)
        };

        var match = matches.FirstOrDefault(candidate => candidate.Success);
        if (match is null || !match.Success)
        {
            return null;
        }

        return match.Groups["uid"].Value.Replace('_', '-').ToLowerInvariant();
    }

    private static string? ExtractContainerToken(string cgroupSignal, string? podUid)
    {
        var patterns = new[]
        {
            @"cri-containerd-(?<id>[0-9a-fA-F]{12,64})\.scope",
            @"crio-(?<id>[0-9a-fA-F]{12,64})\.scope",
            @"docker-(?<id>[0-9a-fA-F]{12,64})\.scope",
            @"/(?<id>[0-9a-fA-F]{12,64})(?:\.scope)?$"
        };

        foreach (var pattern in patterns)
        {
            var match = Regex.Match(cgroupSignal, pattern, RegexOptions.IgnoreCase);
            if (!match.Success)
            {
                continue;
            }

            var token = match.Groups["id"].Value.ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(token))
            {
                continue;
            }

            var normalizedPodUid = podUid?.Replace("-", string.Empty, StringComparison.Ordinal);
            if (!string.IsNullOrWhiteSpace(normalizedPodUid) && string.Equals(token, normalizedPodUid, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return token;
        }

        return null;
    }
}
