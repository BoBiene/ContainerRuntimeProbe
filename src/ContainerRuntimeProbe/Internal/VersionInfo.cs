using System.Reflection;
using System.Text;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Internal;

/// <summary>Helper to extract probe tool version and git commit information.</summary>
internal static class VersionInfo
{
    /// <summary>Returns probe tool metadata with version and git commit hash if available.</summary>
    public static ProbeToolMetadata GetProbeToolMetadata()
    {
        var version = GetAssemblyVersion();
        var gitCommitHash = GetGitCommitHash();
        return new ProbeToolMetadata(version, gitCommitHash);
    }

    /// <summary>Gets assembly version from AssemblyInformationalVersion attribute.</summary>
    private static string GetAssemblyVersion()
    {
        var assembly = typeof(VersionInfo).Assembly;
        var informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;

        return informationalVersion ?? "unknown";
    }

    /// <summary>
    /// Extracts git commit hash. Prefers the hash embedded by MinVer in
    /// <see cref="AssemblyInformationalVersionAttribute"/> as <c>{version}+{hash}</c>
    /// (works inside Docker containers and CI). Falls back to reading <c>.git/HEAD</c>
    /// for local dev builds where MinVer may not have embedded the hash.
    /// </summary>
    private static string? GetGitCommitHash()
    {
        // Primary: parse hash from AssemblyInformationalVersion suffix (+{hash}).
        // MinVer always embeds the full 40-char SHA-1 commit hash there.
        var informationalVersion = typeof(VersionInfo).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;

        if (!string.IsNullOrWhiteSpace(informationalVersion))
        {
            var plusIndex = informationalVersion.IndexOf('+', StringComparison.Ordinal);
            if (plusIndex >= 0)
            {
                var candidate = informationalVersion[(plusIndex + 1)..];
                if (IsHexHash(candidate))
                    return candidate;
            }
        }

        // Fallback: walk up and read .git/HEAD (works in local dev without MinVer tags).
        try
        {
            var assemblyDir = Path.GetDirectoryName(typeof(VersionInfo).Assembly.Location);
            if (string.IsNullOrEmpty(assemblyDir))
                return null;

            var gitDir = FindGitDirectory(assemblyDir);
            if (gitDir is null)
                return null;

            var headFile = Path.Combine(gitDir, "HEAD");
            if (!File.Exists(headFile))
                return null;

            var headContent = File.ReadAllText(headFile).Trim();

            if (headContent.StartsWith("ref:", StringComparison.Ordinal))
            {
                var refPath = headContent[5..].Trim();
                var refFile = Path.Combine(gitDir, refPath);
                if (File.Exists(refFile))
                {
                    var hash = File.ReadAllText(refFile).Trim();
                    return IsHexHash(hash) ? hash : null;
                }
            }

            return IsHexHash(headContent) ? headContent : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsHexHash(string value)
        => (value.Length == 40 || value.Length == 64) // SHA-1 or SHA-256
            && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    /// <summary>Walks up directory tree to find .git directory.</summary>
    private static string? FindGitDirectory(string startPath)
    {
        var current = new DirectoryInfo(startPath);
        const int maxLevels = 10;
        var level = 0;

        while (current is not null && level < maxLevels)
        {
            var gitPath = Path.Combine(current.FullName, ".git");
            if (Directory.Exists(gitPath))
                return gitPath;

            current = current.Parent;
            level++;
        }

        return null;
    }
}
