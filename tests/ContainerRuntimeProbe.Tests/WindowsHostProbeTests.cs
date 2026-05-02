using System.Runtime.InteropServices;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;
using ContainerRuntimeProbe.Probes;
using Microsoft.Win32;

namespace ContainerRuntimeProbe.Tests;

public sealed class WindowsHostProbeTests
{
    [Fact]
    public async Task WindowsHostProbe_ExtractsKernelAndRegistrySignals()
    {
        var registryValues = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["SystemManufacturer"] = "Microsoft Corporation",
            ["SystemProductName"] = "Virtual Machine",
            ["SystemFamily"] = "Hyper-V",
            ["SystemVersion"] = "7.0",
            ["BaseBoardManufacturer"] = "Microsoft Corporation",
            ["BaseBoardProduct"] = "Virtual Machine",
            ["EnclosureManufacturer"] = "Microsoft Corporation",
            ["BIOSVendor"] = "Microsoft Corporation"
        };

        var probe = CreateWindowsProbe(
            registryValues,
            valueName => valueName switch
            {
                "Identifier" => "AMD64 Family 25 Model 68 Stepping 1",
                "VendorIdentifier" => "AuthenticAMD",
                "ProcessorNameString" => "AMD Ryzen 9 6900HX with Radeon Graphics",
                _ => null
            },
            valueName => valueName switch
            {
                "ProductName" => "Windows 11 Pro",
                "DisplayVersion" => "24H2",
                "MachineGuid" => "9f8b2b2f-6d45-4a28-90ea-3c3a2f06d111",
                _ => null
            },
            () => (67947499520UL, 26294513664UL));

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Equal("proc-files", result.ProbeId);
        Assert.Equal(ProbeOutcome.Success, result.Outcome);
        AssertWindowsEvidence(result.Evidence);
    }

    [Fact]
    public async Task WindowsHostProbe_ReadsMachineGuid_FromCryptographyRegistryPath()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var expected = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", null)?.ToString();
        Assert.False(string.IsNullOrWhiteSpace(expected));

        var probe = new WindowsHostProbe();
        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Contains(result.Evidence, item => item.Key == "windows.machine_guid" && item.Value == expected);
    }

    [Fact]
    public async Task WindowsHostProbe_NormalizesWindows11ProductName_WhenRegistryStillReportsWindows10()
    {
        var probe = new WindowsHostProbe(
            () => true,
            _ => null,
            _ => null,
            valueName => valueName switch
            {
                "ProductName" => "Windows 10 Pro",
                "DisplayVersion" => "24H2",
                _ => null
            },
            () => Architecture.X64,
            () => "Microsoft Windows 10.0.26200",
            () => 16,
            () => (null, null));

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Contains(result.Evidence, item => item.Key == "windows.product_name" && item.Value == "Windows 11 Pro");
    }

    [Fact]
    public void WindowsHostProbe_NormalizeWindowsProductName_KeepsWindows10ForOlderBuilds()
    {
        var productName = WindowsHostProbe.NormalizeWindowsProductName("Windows 10 Pro", "10.0.19045");

        Assert.Equal("Windows 10 Pro", productName);
    }

    [Fact]
    public async Task WindowsHostProbe_ReportsNotSupported_OutsideWindows()
    {
        var probe = new WindowsHostProbe(
            () => false,
            _ => throw new InvalidOperationException("Registry access should not occur when probe is unsupported."),
            _ => throw new InvalidOperationException("CPU registry access should not occur when probe is unsupported."),
            _ => throw new InvalidOperationException("CurrentVersion registry access should not occur when probe is unsupported."),
            () => Architecture.X64,
            () => "Microsoft Windows 10.0.26200",
            () => 16,
            () => throw new InvalidOperationException("Memory access should not occur when probe is unsupported."));

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Equal("proc-files", result.ProbeId);
        Assert.Equal(ProbeOutcome.NotSupported, result.Outcome);
        Assert.Empty(result.Evidence);
    }

    [Fact]
    public async Task WindowsTpmProbe_ReportsDeviceInfo_WhenAvailable()
    {
        var probe = new WindowsTpmProbe(
            () => true,
            () => new WindowsTpmDeviceInfo(ProbeOutcome.Success, "2.0", "3", "0x00010002"));

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Equal("windows-trust", result.ProbeId);
        Assert.Equal(ProbeOutcome.Success, result.Outcome);
        Assert.Contains(result.Evidence, item => item.Key == "trust.windows.tpm.outcome" && item.Value == "Success");
        Assert.Contains(result.Evidence, item => item.Key == "trust.windows.tpm.version" && item.Value == "2.0");
        Assert.Contains(result.Evidence, item => item.Key == "trust.windows.tpm.interface_type" && item.Value == "3");
        Assert.Contains(result.Evidence, item => item.Key == "trust.windows.tpm.implementation_revision" && item.Value == "0x00010002");
    }

    private static WindowsHostProbe CreateWindowsProbe(
        IReadOnlyDictionary<string, string> biosValues,
        Func<string, string?> cpuValueFactory,
        Func<string, string?> currentVersionValueFactory,
        Func<(ulong? TotalBytes, ulong? AvailableBytes)> physicalMemoryFactory)
        => new(
            () => true,
            valueName => biosValues.TryGetValue(valueName, out var value) ? value : null,
            cpuValueFactory,
            currentVersionValueFactory,
            () => Architecture.X64,
            () => "Microsoft Windows 10.0.26200",
            () => 16,
            physicalMemoryFactory);

    private static void AssertWindowsEvidence(IReadOnlyList<EvidenceItem> evidence)
    {
        Assert.Contains(evidence, item => item.Key == "kernel.name" && item.Value == "Microsoft Windows");
        Assert.Contains(evidence, item => item.Key == "kernel.release" && item.Value == "10.0.26200");
        Assert.Contains(evidence, item => item.Key == "kernel.architecture" && item.Value == "x86_64");
        Assert.Contains(evidence, item => item.Key == "windows.product_name" && item.Value == "Windows 11 Pro");
        Assert.Contains(evidence, item => item.Key == "windows.display_version" && item.Value == "24H2");
        Assert.Contains(evidence, item => item.Key == "windows.machine_guid" && item.Value == "9f8b2b2f-6d45-4a28-90ea-3c3a2f06d111" && item.Sensitivity == EvidenceSensitivity.Sensitive);
        Assert.Contains(evidence, item => item.Key == "cpu.logical_processors" && item.Value == "16");
        Assert.Contains(evidence, item => item.Key == "cpu.vendor" && item.Value == "AuthenticAMD");
        Assert.Contains(evidence, item => item.Key == "cpu.model_name" && item.Value == "AMD Ryzen 9 6900HX with Radeon Graphics");
        Assert.Contains(evidence, item => item.Key == "cpu.family" && item.Value == "25");
        Assert.Contains(evidence, item => item.Key == "cpu.model" && item.Value == "68");
        Assert.Contains(evidence, item => item.Key == "cpu.stepping" && item.Value == "1");
        Assert.Contains(evidence, item => item.Key == "memory.mem_total_bytes" && item.Value == "67947499520");
        Assert.Contains(evidence, item => item.Key == "memory.mem_available_bytes" && item.Value == "26294513664");
        Assert.Contains(evidence, item => item.Key == "dmi.sys_vendor" && item.Value == "Microsoft Corporation");
        Assert.Contains(evidence, item => item.Key == "dmi.product_name" && item.Value == "Virtual Machine");
        Assert.Contains(evidence, item => item.Key == "dmi.product_family" && item.Value == "Hyper-V");
        Assert.Contains(evidence, item => item.Key == "dmi.board_vendor" && item.Value == "Microsoft Corporation");
        Assert.Contains(evidence, item => item.Key == "dmi.board_name" && item.Value == "Virtual Machine");
        Assert.Contains(evidence, item => item.Key == "dmi.chassis_vendor" && item.Value == "Microsoft Corporation");
        Assert.Contains(evidence, item => item.Key == "dmi.bios_vendor" && item.Value == "Microsoft Corporation");
    }

    [Fact]
    public async Task WindowsTpmProbe_ReportsNotSupported_OutsideWindows()
    {
        var probe = new WindowsTpmProbe(
            () => false,
            () => throw new InvalidOperationException("TPM access should not occur when probe is unsupported."));

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Equal("windows-trust", result.ProbeId);
        Assert.Equal(ProbeOutcome.NotSupported, result.Outcome);
        Assert.Empty(result.Evidence);
    }
}