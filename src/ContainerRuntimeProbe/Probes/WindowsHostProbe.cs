using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Probes;

internal sealed class WindowsHostProbe : IProbe
{
    private const string BiosRegistryKeyPath = @"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS";

    private readonly Func<bool> _isWindows;
    private readonly Func<string, string?> _readRegistryValue;
    private readonly Func<Architecture> _getOsArchitecture;
    private readonly Func<string> _getOsDescription;
    private readonly Func<int> _getLogicalProcessorCount;

    public string Id => "proc-files";

    public WindowsHostProbe()
        : this(
            () => OperatingSystem.IsWindows(),
            ReadRegistryValueIfSupported,
            () => RuntimeInformation.OSArchitecture,
            () => RuntimeInformation.OSDescription,
            () => Environment.ProcessorCount)
    {
    }

    internal WindowsHostProbe(
        Func<bool> isWindows,
        Func<string, string?> readRegistryValue,
        Func<Architecture> getOsArchitecture,
        Func<string> getOsDescription,
        Func<int> getLogicalProcessorCount)
    {
        _isWindows = isWindows;
        _readRegistryValue = readRegistryValue;
        _getOsArchitecture = getOsArchitecture;
        _getOsDescription = getOsDescription;
        _getLogicalProcessorCount = getLogicalProcessorCount;
    }

    public Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();

        if (!_isWindows())
        {
            sw.Stop();
            return Task.FromResult(new ProbeResult(Id, ProbeOutcome.NotSupported, [], "Windows host signals are not available on this platform.", sw.Elapsed));
        }

        var evidence = new List<EvidenceItem>();
        AddEvidenceIfPresent(evidence, "kernel.architecture", HostParsing.NormalizeArchitectureRaw(_getOsArchitecture()));
        AddEvidenceIfPresent(evidence, "cpu.logical_processors", _getLogicalProcessorCount().ToString(CultureInfo.InvariantCulture));

        var kernel = ParseWindowsKernel(_getOsDescription());
        AddEvidenceIfPresent(evidence, "kernel.name", kernel.Name);
        AddEvidenceIfPresent(evidence, "kernel.release", kernel.Release);
        AddEvidenceIfPresent(evidence, "kernel.version", kernel.Version);

        AddRegistryEvidence(evidence, "SystemManufacturer", "dmi.sys_vendor");
        AddRegistryEvidence(evidence, "SystemProductName", "dmi.product_name");
        AddRegistryEvidence(evidence, "SystemFamily", "dmi.product_family");
        AddRegistryEvidence(evidence, "SystemVersion", "dmi.product_version");
        AddRegistryEvidence(evidence, "BaseBoardManufacturer", "dmi.board_vendor");
        AddRegistryEvidence(evidence, "BaseBoardProduct", "dmi.board_name");
        AddRegistryEvidence(evidence, "BIOSVendor", "dmi.bios_vendor");

        sw.Stop();
        return Task.FromResult(new ProbeResult(Id, ProbeOutcome.Success, evidence, Duration: sw.Elapsed));
    }

    private void AddRegistryEvidence(List<EvidenceItem> evidence, string registryValueName, string evidenceKey)
        => AddEvidenceIfPresent(evidence, evidenceKey, _readRegistryValue(registryValueName));

    private static void AddEvidenceIfPresent(List<EvidenceItem> evidence, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evidence.Add(new EvidenceItem("proc-files", key, value.Trim()));
        }
    }

    private static string? ReadRegistryValueIfSupported(string valueName)
        => OperatingSystem.IsWindows() ? ReadRegistryValue(valueName) : null;

    [SupportedOSPlatform("windows")]
    private static string? ReadRegistryValue(string valueName)
    {
        try
        {
            return Registry.GetValue(BiosRegistryKeyPath, valueName, null)?.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static (string? Name, string? Release, string? Version) ParseWindowsKernel(string osDescription)
    {
        var normalized = osDescription?.Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return ("Microsoft Windows", null, null);
        }

        var match = Regex.Match(normalized, @"^(?<name>.+?)\s+(?<version>\d+(?:\.\d+){1,3})$");
        if (!match.Success)
        {
            return (normalized, null, null);
        }

        var name = match.Groups["name"].Value.Trim();
        var version = match.Groups["version"].Value.Trim();
        return (name, version, version);
    }
}