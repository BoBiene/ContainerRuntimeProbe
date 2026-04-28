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

    /// <summary>Attempts to read git commit hash from .git/HEAD and git index files.</summary>
    private static string? GetGitCommitHash()
    {
        try
        {
            // Try to find .git directory (walk up from assembly location)
            var assemblyDir = Path.GetDirectoryName(typeof(VersionInfo).Assembly.Location);
            if (string.IsNullOrEmpty(assemblyDir))
                return null;

            var gitDir = FindGitDirectory(assemblyDir);
            if (gitDir is null)
                return null;

            // Read HEAD to get current branch ref or commit hash
            var headFile = Path.Combine(gitDir, "HEAD");
            if (!File.Exists(headFile))
                return null;

            var headContent = File.ReadAllText(headFile).Trim();

            // If HEAD contains "ref: refs/heads/...", read that ref file
            if (headContent.StartsWith("ref:"))
            {
                var refPath = headContent.Substring(5).Trim();
                var refFile = Path.Combine(gitDir, refPath);
                if (File.Exists(refFile))
                {
                    return File.ReadAllText(refFile).Trim();
                }
            }

            // HEAD might be a direct commit hash (detached state)
            if (headContent.Length == 40 || headContent.Length == 64) // SHA1 or SHA256
            {
                return headContent;
            }

            return null;
        }
        catch
        {
            // If anything fails, return null - version is still available
            return null;
        }
    }

    /// <summary>Walks up directory tree to find .git directory.</summary>
    private static string? FindGitDirectory(string startPath)
    {
        var current = new DirectoryInfo(startPath);
        const int maxLevels = 10; // Prevent infinite loops
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
