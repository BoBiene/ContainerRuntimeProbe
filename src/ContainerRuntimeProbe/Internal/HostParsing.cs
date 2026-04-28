using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Classification;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Internal;

internal sealed record ParsedOsRelease(
    OperatingSystemFamily Family,
    string? Id,
    IReadOnlyList<string> IdLike,
    string? Name,
    string? PrettyName,
    string? Version,
    string? VersionId,
    string? VersionCodename,
    string? BuildId,
    string? Variant,
    string? VariantId,
    string? HomeUrl,
    string? SupportUrl,
    string? BugReportUrl);

internal sealed record ParsedKernelInfo(
    string? Name,
    string? Release,
    string? Version,
    string? Compiler,
    KernelFlavor Flavor);

internal sealed record ParsedCpuInfo(
    int? LogicalProcessorCount,
    string? Vendor,
    string? ModelName,
    string? Family,
    string? Model,
    string? Stepping,
    string? Microcode,
    int? FlagsCount,
    string? FlagsHash,
    string? Hardware,
    string? Revision,
    string? Serial);

internal sealed record ParsedMemoryInfo(
    long? MemTotalBytes,
    long? MemAvailableBytes);

internal sealed record ParsedRuntimeHostInfo(
    OperatingSystemFamily Family,
    string? Name,
    string? Version,
    string? KernelVersion,
    string? RawArchitecture,
    RuntimeReportedHostSource Source,
    IReadOnlyList<string> EvidenceReferences);

internal sealed record ParsedCloudHostInfo(
    string? MachineType,
    string? Region,
    string? Zone,
    string? OsType,
    string? RawArchitecture,
    RuntimeReportedHostSource Source,
    IReadOnlyList<string> EvidenceReferences);

internal static class HostParsing
{
    public static ParsedOsRelease ParseOsRelease(string text)
    {
        var values = Parsing.ParseKeyValueLines(text.Split('\n', StringSplitOptions.RemoveEmptyEntries));
        values.TryGetValue("ID", out var id);
        values.TryGetValue("NAME", out var name);
        values.TryGetValue("PRETTY_NAME", out var prettyName);
        values.TryGetValue("VERSION", out var version);
        values.TryGetValue("VERSION_ID", out var versionId);
        values.TryGetValue("VERSION_CODENAME", out var versionCodename);
        values.TryGetValue("BUILD_ID", out var buildId);
        values.TryGetValue("VARIANT", out var variant);
        values.TryGetValue("VARIANT_ID", out var variantId);
        values.TryGetValue("HOME_URL", out var homeUrl);
        values.TryGetValue("SUPPORT_URL", out var supportUrl);
        values.TryGetValue("BUG_REPORT_URL", out var bugReportUrl);

        var idLike = values.TryGetValue("ID_LIKE", out var idLikeRaw)
            ? idLikeRaw.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];

        return new ParsedOsRelease(
            NormalizeOperatingSystemFamily(id, idLike, name, prettyName),
            id,
            idLike,
            name,
            prettyName,
            version,
            versionId,
            versionCodename,
            buildId,
            variant,
            variantId,
            homeUrl,
            supportUrl,
            bugReportUrl);
    }

    public static ArchitectureKind NormalizeArchitecture(string? rawArchitecture)
        => rawArchitecture?.Trim().ToLowerInvariant() switch
        {
            "x86" or "i386" or "i486" or "i586" or "i686" => ArchitectureKind.X86,
            "x86_64" or "amd64" => ArchitectureKind.X64,
            "arm" or "armv6l" or "armv7l" => ArchitectureKind.Arm,
            "aarch64" or "arm64" => ArchitectureKind.Arm64,
            "s390x" => ArchitectureKind.S390x,
            "ppc64le" => ArchitectureKind.Ppc64le,
            "riscv64" => ArchitectureKind.RiscV64,
            "wasm" or "wasm32" or "wasm64" => ArchitectureKind.Wasm,
            _ => ArchitectureKind.Unknown
        };

    public static string NormalizeArchitectureRaw(Architecture architecture)
        => architecture switch
        {
            Architecture.X64 => "x86_64",
            Architecture.X86 => "x86",
            Architecture.Arm64 => "arm64",
            Architecture.Arm => "arm",
            Architecture.S390x => "s390x",
            _ => architecture.ToString().ToLowerInvariant()
        };

    public static ParsedKernelInfo ParseKernel(string? procVersion, string? osRelease, string? osType, string? kernelVersion)
    {
        var release = CleanValue(osRelease);
        var name = CleanValue(osType);
        var version = CleanValue(kernelVersion);
        var compiler = ExtractCompiler(procVersion);

        if (!string.IsNullOrWhiteSpace(procVersion))
        {
            var parts = procVersion.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > 2)
            {
                name ??= parts[0];
                release ??= parts[2];
                version ??= ExtractKernelVersion(procVersion);
            }
        }

        return new ParsedKernelInfo(
            name ?? "Linux",
            release,
            version,
            compiler,
            InferKernelFlavor($"{procVersion}\n{osRelease}\n{kernelVersion}"));
    }

    public static ParsedCpuInfo ParseCpuInfo(string text)
    {
        var sections = text.Split("\n\n", StringSplitOptions.RemoveEmptyEntries);
        var first = sections.FirstOrDefault() ?? string.Empty;
        var values = Parsing.ParseKeyValueLines(first.Split('\n'), ':');
        var logicalCount = sections.SelectMany(section => section.Split('\n'))
            .Count(line => line.TrimStart().StartsWith("processor", StringComparison.OrdinalIgnoreCase));
        if (logicalCount == 0 && values.TryGetValue("processor", out _))
        {
            logicalCount = 1;
        }

        var flags = GetFirstValue(values, "flags", "Features");
        var normalizedFlags = flags?
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(flag => flag.Trim().ToLowerInvariant())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(flag => flag, StringComparer.Ordinal)
            .ToArray();

        return new ParsedCpuInfo(
            logicalCount == 0 ? null : logicalCount,
            GetFirstValue(values, "vendor_id", "CPU implementer"),
            GetFirstValue(values, "model name", "Processor"),
            GetFirstValue(values, "cpu family", "CPU architecture"),
            values.GetValueOrDefault("model"),
            values.GetValueOrDefault("stepping"),
            values.GetValueOrDefault("microcode"),
            normalizedFlags?.Length,
            normalizedFlags is { Length: > 0 } ? ComputeSha256Hex(string.Join('\n', normalizedFlags)) : null,
            values.GetValueOrDefault("Hardware"),
            values.GetValueOrDefault("Revision"),
            values.GetValueOrDefault("Serial"));
    }

    public static string? SanitizeCpuSerial(string? serial, bool includeSensitive)
        => string.IsNullOrWhiteSpace(serial) ? null : includeSensitive ? serial.Trim() : "redacted";

    public static int? ParseCpuRangeCount(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var total = 0;
        foreach (var range in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var bounds = range.Split('-', StringSplitOptions.TrimEntries);
            if (bounds.Length == 1 && int.TryParse(bounds[0], CultureInfo.InvariantCulture, out _))
            {
                total++;
            }
            else if (bounds.Length == 2 &&
                     int.TryParse(bounds[0], CultureInfo.InvariantCulture, out var start) &&
                     int.TryParse(bounds[1], CultureInfo.InvariantCulture, out var end) &&
                     end >= start)
            {
                total += end - start + 1;
            }
        }

        return total == 0 ? null : total;
    }

    public static ParsedMemoryInfo ParseMemInfo(string text)
    {
        var values = Parsing.ParseKeyValueLines(text.Split('\n', StringSplitOptions.RemoveEmptyEntries), ':');
        return new ParsedMemoryInfo(
            ParseMemInfoKb(values.GetValueOrDefault("MemTotal")),
            ParseMemInfoKb(values.GetValueOrDefault("MemAvailable")));
    }

    public static long? ParseNullableLong(string? value)
        => long.TryParse(CleanValue(value), CultureInfo.InvariantCulture, out var parsed) ? parsed : null;

    public static string NormalizeCpuFamily(string? vendor, string? modelName)
    {
        var joined = $"{vendor} {modelName}".ToLowerInvariant();
        if (joined.Contains("intel", StringComparison.Ordinal))
        {
            return "IntelXeon";
        }

        if (joined.Contains("amd", StringComparison.Ordinal))
        {
            return "AMD";
        }

        if (joined.Contains("arm", StringComparison.Ordinal))
        {
            return "ARM";
        }

        return string.IsNullOrWhiteSpace(vendor) ? "Unknown" : vendor!;
    }

    public static string? NormalizeModelName(string? modelName)
    {
        if (string.IsNullOrWhiteSpace(modelName))
        {
            return null;
        }

        var normalized = string.Join(' ', modelName.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return normalized.Length > 96 ? normalized[..96] : normalized;
    }

    public static string NormalizeMemoryBucket(long? bytes)
    {
        if (bytes is null or <= 0)
        {
            return "unknown";
        }

        var gib = bytes.Value / (1024d * 1024d * 1024d);
        var bucket = Math.Max(1, (int)Math.Round(gib, MidpointRounding.AwayFromZero));
        return $"{bucket}GiB";
    }

    public static string? NormalizeVersionMajorMinor(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return null;
        }

        var match = System.Text.RegularExpressions.Regex.Match(version, @"\d+(?:\.\d+)?");
        return match.Success ? match.Value : null;
    }

    public static ParsedRuntimeHostInfo? ParseDockerInfo(string json, string probeId)
    {
        using var doc = ParseJson(json);
        if (doc is null)
        {
            return null;
        }

        var root = doc.RootElement;
        var operatingSystem = GetString(root, "OperatingSystem");
        var osType = GetString(root, "OSType");
        var architecture = GetString(root, "Architecture");
        var kernelVersion = GetString(root, "KernelVersion");
        return new ParsedRuntimeHostInfo(
            NormalizeOperatingSystemFamily(operatingSystem, [], operatingSystem, operatingSystem, fallbackType: osType),
            operatingSystem,
            ExtractOsVersion(operatingSystem),
            kernelVersion,
            architecture,
            RuntimeReportedHostSource.DockerInfo,
            [$"{probeId}.docker.info"]);
    }

    public static ParsedRuntimeHostInfo? ParsePodmanInfo(string json, string probeId)
    {
        using var doc = ParseJson(json);
        if (doc is null)
        {
            return null;
        }

        var host = TryGetProperty(doc.RootElement, "host");
        if (host is null)
        {
            return null;
        }

        var distribution = TryGetProperty(host.Value, "distribution");
        var name = distribution is { ValueKind: JsonValueKind.Object } ? GetString(distribution.Value, "distribution") : null;
        var version = distribution is { ValueKind: JsonValueKind.Object } ? GetString(distribution.Value, "version") : null;
        return new ParsedRuntimeHostInfo(
            NormalizeOperatingSystemFamily(name, [], name, name),
            name,
            version,
            GetString(host.Value, "kernel"),
            GetString(host.Value, "arch"),
            RuntimeReportedHostSource.PodmanInfo,
            [$"{probeId}.podman.info"]);
    }

    public static ParsedRuntimeHostInfo? ParseKubernetesNodeInfo(string json, string probeId)
    {
        using var doc = ParseJson(json);
        if (doc is null)
        {
            return null;
        }

        var status = TryGetProperty(doc.RootElement, "status");
        var nodeInfo = status is { ValueKind: JsonValueKind.Object } ? TryGetProperty(status.Value, "nodeInfo") : null;
        if (nodeInfo is not { ValueKind: JsonValueKind.Object })
        {
            return null;
        }

        var osImage = GetString(nodeInfo.Value, "osImage");
        var operatingSystem = GetString(nodeInfo.Value, "operatingSystem");
        return new ParsedRuntimeHostInfo(
            NormalizeOperatingSystemFamily(osImage, [], operatingSystem, osImage, fallbackType: operatingSystem),
            osImage ?? operatingSystem,
            ExtractOsVersion(osImage),
            GetString(nodeInfo.Value, "kernelVersion"),
            GetString(nodeInfo.Value, "architecture"),
            RuntimeReportedHostSource.KubernetesNodeInfo,
            [$"{probeId}.nodeInfo"]);
    }

    public static ParsedCloudHostInfo? ParseAwsIdentity(string json, string probeId)
    {
        using var doc = ParseJson(json);
        if (doc is null)
        {
            return null;
        }

        return new ParsedCloudHostInfo(
            GetString(doc.RootElement, "instanceType"),
            GetString(doc.RootElement, "region"),
            GetString(doc.RootElement, "availabilityZone"),
            null,
            GetString(doc.RootElement, "architecture"),
            RuntimeReportedHostSource.AwsMetadata,
            [$"{probeId}.aws.identity"]);
    }

    public static ParsedCloudHostInfo? ParseAzureMetadata(string json, string probeId)
    {
        using var doc = ParseJson(json);
        if (doc is null)
        {
            return null;
        }

        var compute = TryGetProperty(doc.RootElement, "compute");
        if (compute is not { ValueKind: JsonValueKind.Object })
        {
            return null;
        }

        return new ParsedCloudHostInfo(
            GetString(compute.Value, "vmSize"),
            GetString(compute.Value, "location"),
            GetString(compute.Value, "zone"),
            GetString(compute.Value, "osType"),
            null,
            RuntimeReportedHostSource.AzureImds,
            [$"{probeId}.azure.instance"]);
    }

    public static ParsedCloudHostInfo? ParseOciMetadata(string json, string probeId)
    {
        using var doc = ParseJson(json);
        if (doc is null)
        {
            return null;
        }

        return new ParsedCloudHostInfo(
            GetString(doc.RootElement, "shape"),
            GetString(doc.RootElement, "region"),
            GetString(doc.RootElement, "availabilityDomain"),
            null,
            null,
            RuntimeReportedHostSource.OciMetadata,
            [$"{probeId}.oci.instance"]);
    }

    public static string ComputeFingerprint(IReadOnlyDictionary<string, string> components)
    {
        var canonical = string.Join('\n', components
            .OrderBy(kvp => kvp.Key, StringComparer.Ordinal)
            .Select(kvp => $"{kvp.Key}={kvp.Value}"));
        return $"sha256:{ComputeSha256Hex(canonical)}";
    }

    public static string ComputeSha256Hex(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static OperatingSystemFamily NormalizeOperatingSystemFamily(
        string? id,
        IEnumerable<string>? idLike,
        string? name,
        string? prettyName,
        string? fallbackType = null)
    {
        var candidates = new[] { id, name, prettyName, fallbackType }
            .Concat(idLike ?? [])
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!.ToLowerInvariant())
            .ToList();

        if (candidates.Count == 0)
        {
            return OperatingSystemFamily.Unknown;
        }

        if (candidates.Any(value => value.Contains("azure linux", StringComparison.Ordinal) || value == "azurelinux"))
        {
            return OperatingSystemFamily.AzureLinux;
        }

        if (candidates.Any(value => value.Contains("mariner", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.Mariner;
        }

        if (candidates.Any(value => value.Contains("ubuntu", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.Ubuntu;
        }

        if (candidates.Any(value => value.Contains("debian", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.Debian;
        }

        if (candidates.Any(value => value.Contains("alpine", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.Alpine;
        }

        if (candidates.Any(value => value.Contains("amazon linux", StringComparison.Ordinal) || value == "amzn"))
        {
            return OperatingSystemFamily.AmazonLinux;
        }

        if (candidates.Any(value => value.Contains("red hat", StringComparison.Ordinal) || value == "rhel"))
        {
            return OperatingSystemFamily.RedHatEnterpriseLinux;
        }

        if (candidates.Any(value => value.Contains("centos", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.CentOS;
        }

        if (candidates.Any(value => value.Contains("fedora", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.Fedora;
        }

        if (candidates.Any(value => value.Contains("rocky", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.RockyLinux;
        }

        if (candidates.Any(value => value.Contains("alma", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.AlmaLinux;
        }

        if (candidates.Any(value => value.Contains("sles", StringComparison.Ordinal) || value.Contains("suse", StringComparison.Ordinal)))
        {
            return candidates.Any(value => value.Contains("opensuse", StringComparison.Ordinal)) ? OperatingSystemFamily.OpenSuse : OperatingSystemFamily.Suse;
        }

        if (candidates.Any(value => value.Contains("oracle", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.OracleLinux;
        }

        if (candidates.Any(value => value.Contains("wolfi", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.Wolfi;
        }

        if (candidates.Any(value => value.Contains("busybox", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.BusyBox;
        }

        if (candidates.Any(value => value.Contains("distroless", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.Distroless;
        }

        if (candidates.Any(value => value.Contains("photon", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.PhotonOS;
        }

        if (candidates.Any(value => value.Contains("flatcar", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.Flatcar;
        }

        if (candidates.Any(value => value.Contains("bottlerocket", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.Bottlerocket;
        }

        if (candidates.Any(value => value.Contains("rancher", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.RancherOS;
        }

        if (candidates.Any(value => value.Contains("talos", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.Talos;
        }

        if (candidates.Any(value => value.Contains("container-optimized", StringComparison.Ordinal) || value.Contains("cos", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.ContainerOptimizedOS;
        }

        if (candidates.Any(value => value.Contains("windows server core", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.WindowsServerCore;
        }

        if (candidates.Any(value => value.Contains("windows nanoserver", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.WindowsNanoServer;
        }

        if (candidates.Any(value => value.Contains("windows server", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.WindowsServer;
        }

        if (candidates.Any(value => value.Contains("windows", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.Windows;
        }

        if (candidates.Any(value => value.Contains("mac", StringComparison.Ordinal) || value.Contains("darwin", StringComparison.Ordinal)))
        {
            return OperatingSystemFamily.MacOS;
        }

        return candidates.Any(value => value.Contains("linux", StringComparison.Ordinal))
            ? OperatingSystemFamily.Linux
            : OperatingSystemFamily.Unknown;
    }

    private static JsonDocument? ParseJson(string json)
    {
        try
        {
            return JsonDocument.Parse(json);
        }
        catch
        {
            return null;
        }
    }

    private static JsonElement? TryGetProperty(JsonElement element, string name)
        => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) ? value : null;

    private static string? GetString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => bool.TrueString,
            JsonValueKind.False => bool.FalseString,
            _ => null
        };
    }

    private static string? GetFirstValue(IReadOnlyDictionary<string, string> values, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static string? ExtractCompiler(string? procVersion)
    {
        if (string.IsNullOrWhiteSpace(procVersion))
        {
            return null;
        }

        var gccIndex = procVersion.IndexOf("gcc", StringComparison.OrdinalIgnoreCase);
        if (gccIndex >= 0)
        {
            var end = procVersion.IndexOf(')', gccIndex);
            return end > gccIndex ? procVersion[gccIndex..end].Trim() : procVersion[gccIndex..].Trim();
        }

        return null;
    }

    private static string? ExtractKernelVersion(string procVersion)
    {
        var versionIndex = procVersion.IndexOf("version ", StringComparison.OrdinalIgnoreCase);
        return versionIndex >= 0 ? procVersion[(versionIndex + "version ".Length)..].Trim() : null;
    }

    private static KernelFlavor InferKernelFlavor(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return KernelFlavor.Unknown;
        }

        var lower = text.ToLowerInvariant();
        foreach (var signal in DetectionMaps.KernelFlavorSignals)
        {
            if (lower.Contains(signal.Signal, StringComparison.Ordinal))
            {
                return signal.Flavor;
            }
        }

        if (lower.Contains("rt", StringComparison.Ordinal) || lower.Contains("realtime", StringComparison.Ordinal))
        {
            return KernelFlavor.Realtime;
        }

        return KernelFlavor.Generic;
    }

    private static long? ParseMemInfoKb(string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return null;
        }

        var parts = rawValue.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts.Length > 0 && long.TryParse(parts[0], CultureInfo.InvariantCulture, out var kb) ? kb * 1024 : null;
    }

    private static string? CleanValue(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string? ExtractOsVersion(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        var match = System.Text.RegularExpressions.Regex.Match(name, @"\d+(?:\.\d+){0,2}(?:\s*LTS)?");
        return match.Success ? match.Value.Trim() : null;
    }

    internal static bool ContainsWsl2Signal(string? value)
        => value?.Contains("microsoft-standard-WSL2", StringComparison.OrdinalIgnoreCase) == true
            || value?.Contains("WSL2", StringComparison.OrdinalIgnoreCase) == true;
}
