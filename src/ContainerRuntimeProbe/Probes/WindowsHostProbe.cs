using System.Diagnostics;
using System.Globalization;
using System.ComponentModel;
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
    private const string CpuRegistryKeyPath = @"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0";
    private const string CurrentVersionRegistryKeyPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    private const string CryptographyRegistryKeyPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography";

    private readonly Func<bool> _isWindows;
    private readonly Func<string, string?> _readBiosRegistryValue;
    private readonly Func<string, string?> _readCpuRegistryValue;
    private readonly Func<string, string?> _readCurrentVersionRegistryValue;
    private readonly Func<Architecture> _getOsArchitecture;
    private readonly Func<string> _getOsDescription;
    private readonly Func<int> _getLogicalProcessorCount;
    private readonly Func<(ulong? TotalBytes, ulong? AvailableBytes)> _getPhysicalMemory;

    public string Id => "proc-files";

    public WindowsHostProbe()
        : this(
            () => OperatingSystem.IsWindows(),
            ReadBiosRegistryValueIfSupported,
            ReadCpuRegistryValueIfSupported,
            ReadCurrentVersionRegistryValueIfSupported,
            () => RuntimeInformation.OSArchitecture,
            () => RuntimeInformation.OSDescription,
                () => Environment.ProcessorCount,
                ReadPhysicalMemoryIfSupported)
    {
    }

    internal WindowsHostProbe(
        Func<bool> isWindows,
        Func<string, string?> readBiosRegistryValue,
        Func<string, string?> readCpuRegistryValue,
        Func<string, string?> readCurrentVersionRegistryValue,
        Func<Architecture> getOsArchitecture,
        Func<string> getOsDescription,
        Func<int> getLogicalProcessorCount,
        Func<(ulong? TotalBytes, ulong? AvailableBytes)> getPhysicalMemory)
    {
        _isWindows = isWindows;
        _readBiosRegistryValue = readBiosRegistryValue;
        _readCpuRegistryValue = readCpuRegistryValue;
        _readCurrentVersionRegistryValue = readCurrentVersionRegistryValue;
        _getOsArchitecture = getOsArchitecture;
        _getOsDescription = getOsDescription;
        _getLogicalProcessorCount = getLogicalProcessorCount;
        _getPhysicalMemory = getPhysicalMemory;
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
        var cpuIdentifier = ParseCpuIdentifier(_readCpuRegistryValue("Identifier"));
        AddEvidenceIfPresent(evidence, "cpu.vendor", _readCpuRegistryValue("VendorIdentifier"));
        AddEvidenceIfPresent(evidence, "cpu.model_name", _readCpuRegistryValue("ProcessorNameString"));
        AddEvidenceIfPresent(evidence, "cpu.family", cpuIdentifier.Family);
        AddEvidenceIfPresent(evidence, "cpu.model", cpuIdentifier.Model);
        AddEvidenceIfPresent(evidence, "cpu.stepping", cpuIdentifier.Stepping);
        var memory = _getPhysicalMemory();
        AddEvidenceIfPresent(evidence, "memory.mem_total_bytes", memory.TotalBytes?.ToString(CultureInfo.InvariantCulture));
        AddEvidenceIfPresent(evidence, "memory.mem_available_bytes", memory.AvailableBytes?.ToString(CultureInfo.InvariantCulture));

        var kernel = ParseWindowsKernel(_getOsDescription());
        AddEvidenceIfPresent(evidence, "kernel.name", kernel.Name);
        AddEvidenceIfPresent(evidence, "kernel.release", kernel.Release);
        AddEvidenceIfPresent(evidence, "kernel.version", kernel.Version);
        var productName = NormalizeWindowsProductName(_readCurrentVersionRegistryValue("ProductName"), kernel.Release);
        AddEvidenceIfPresent(evidence, "windows.product_name", productName);
        AddEvidenceIfPresent(evidence, "windows.display_version", _readCurrentVersionRegistryValue("DisplayVersion") ?? _readCurrentVersionRegistryValue("ReleaseId"));
        AddEvidenceIfPresent(evidence, "windows.machine_guid", ReadMachineGuid(), EvidenceSensitivity.Sensitive);

        AddRegistryEvidence(evidence, "SystemManufacturer", "dmi.sys_vendor");
        AddRegistryEvidence(evidence, "SystemProductName", "dmi.product_name");
        AddRegistryEvidence(evidence, "SystemFamily", "dmi.product_family");
        AddRegistryEvidence(evidence, "SystemVersion", "dmi.product_version");
        AddRegistryEvidence(evidence, "BaseBoardManufacturer", "dmi.board_vendor");
        AddRegistryEvidence(evidence, "BaseBoardProduct", "dmi.board_name");
        AddRegistryEvidence(evidence, "EnclosureManufacturer", "dmi.chassis_vendor");
        AddRegistryEvidence(evidence, "BIOSVendor", "dmi.bios_vendor");

        sw.Stop();
        return Task.FromResult(new ProbeResult(Id, ProbeOutcome.Success, evidence, Duration: sw.Elapsed));
    }

    private void AddRegistryEvidence(List<EvidenceItem> evidence, string registryValueName, string evidenceKey)
        => AddEvidenceIfPresent(evidence, evidenceKey, _readBiosRegistryValue(registryValueName));

    private string? ReadMachineGuid()
        => _readCurrentVersionRegistryValue("MachineGuid")
           ?? (OperatingSystem.IsWindows() ? ReadMachineGuidFromCryptographyRegistry() : null);

    private static void AddEvidenceIfPresent(List<EvidenceItem> evidence, string key, string? value, EvidenceSensitivity sensitivity = EvidenceSensitivity.Public)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evidence.Add(new EvidenceItem("proc-files", key, value.Trim(), sensitivity));
        }
    }

    private static string? ReadBiosRegistryValueIfSupported(string valueName)
        => OperatingSystem.IsWindows() ? ReadRegistryValue(BiosRegistryKeyPath, valueName) : null;

    private static string? ReadCpuRegistryValueIfSupported(string valueName)
        => OperatingSystem.IsWindows() ? ReadRegistryValue(CpuRegistryKeyPath, valueName) : null;

    private static string? ReadCurrentVersionRegistryValueIfSupported(string valueName)
        => OperatingSystem.IsWindows() ? ReadRegistryValue(CurrentVersionRegistryKeyPath, valueName) : null;

    [SupportedOSPlatform("windows")]
    private static string? ReadMachineGuidFromCryptographyRegistry()
        => ReadRegistryValue(CryptographyRegistryKeyPath, "MachineGuid");

    private static (ulong? TotalBytes, ulong? AvailableBytes) ReadPhysicalMemoryIfSupported()
    {
        if (!OperatingSystem.IsWindows())
        {
            return (null, null);
        }

        try
        {
            var memoryStatus = new MemoryStatusEx
            {
                Length = (uint)Marshal.SizeOf<MemoryStatusEx>()
            };

            return GlobalMemoryStatusEx(ref memoryStatus)
                ? (memoryStatus.TotalPhysicalBytes, memoryStatus.AvailablePhysicalBytes)
                : (null, null);
        }
        catch
        {
            return (null, null);
        }
    }

    [SupportedOSPlatform("windows")]
    private static string? ReadRegistryValue(string keyPath, string valueName)
    {
        try
        {
            return Registry.GetValue(keyPath, valueName, null)?.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static (string? Family, string? Model, string? Stepping) ParseCpuIdentifier(string? identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            return (null, null, null);
        }

        var match = Regex.Match(
            identifier,
            @"\bFamily\s+(?<family>\d+)\b.*\bModel\s+(?<model>\d+)\b.*\bStepping\s+(?<stepping>\d+)\b",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        return match.Success
            ? (match.Groups["family"].Value, match.Groups["model"].Value, match.Groups["stepping"].Value)
            : (null, null, null);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct MemoryStatusEx
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhysicalBytes;
        public ulong AvailablePhysicalBytes;
        public ulong TotalPageFileBytes;
        public ulong AvailablePageFileBytes;
        public ulong TotalVirtualBytes;
        public ulong AvailableVirtualBytes;
        public ulong AvailableExtendedVirtualBytes;
    }

    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx memoryStatus);

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

    internal static string? NormalizeWindowsProductName(string? productName, string? kernelRelease)
    {
        if (string.IsNullOrWhiteSpace(productName)
            || string.IsNullOrWhiteSpace(kernelRelease)
            || !productName.StartsWith("Windows 10", StringComparison.OrdinalIgnoreCase))
        {
            return productName;
        }

        var segments = kernelRelease.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (segments.Length < 3 || !int.TryParse(segments[2], CultureInfo.InvariantCulture, out var buildNumber) || buildNumber < 22000)
        {
            return productName;
        }

        return "Windows 11" + productName["Windows 10".Length..];
    }
}