using System.Runtime.InteropServices;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Probes;

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
            ["BIOSVendor"] = "Microsoft Corporation"
        };

        var probe = new WindowsHostProbe(
            () => true,
            valueName => registryValues.TryGetValue(valueName, out var value) ? value : null,
            valueName => valueName switch
            {
                "ProductName" => "Windows 11 Pro",
                "DisplayVersion" => "24H2",
                _ => null
            },
            () => Architecture.X64,
            () => "Microsoft Windows 10.0.26200",
            () => 16);

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Equal("proc-files", result.ProbeId);
        Assert.Equal(ProbeOutcome.Success, result.Outcome);
        Assert.Contains(result.Evidence, item => item.Key == "kernel.name" && item.Value == "Microsoft Windows");
        Assert.Contains(result.Evidence, item => item.Key == "kernel.release" && item.Value == "10.0.26200");
        Assert.Contains(result.Evidence, item => item.Key == "kernel.architecture" && item.Value == "x86_64");
        Assert.Contains(result.Evidence, item => item.Key == "windows.product_name" && item.Value == "Windows 11 Pro");
        Assert.Contains(result.Evidence, item => item.Key == "windows.display_version" && item.Value == "24H2");
        Assert.Contains(result.Evidence, item => item.Key == "cpu.logical_processors" && item.Value == "16");
        Assert.Contains(result.Evidence, item => item.Key == "dmi.sys_vendor" && item.Value == "Microsoft Corporation");
        Assert.Contains(result.Evidence, item => item.Key == "dmi.product_name" && item.Value == "Virtual Machine");
        Assert.Contains(result.Evidence, item => item.Key == "dmi.product_family" && item.Value == "Hyper-V");
        Assert.Contains(result.Evidence, item => item.Key == "dmi.board_vendor" && item.Value == "Microsoft Corporation");
        Assert.Contains(result.Evidence, item => item.Key == "dmi.board_name" && item.Value == "Virtual Machine");
        Assert.Contains(result.Evidence, item => item.Key == "dmi.bios_vendor" && item.Value == "Microsoft Corporation");
    }

    [Fact]
    public async Task WindowsHostProbe_ReportsNotSupported_OutsideWindows()
    {
        var probe = new WindowsHostProbe(
            () => false,
            _ => throw new InvalidOperationException("Registry access should not occur when probe is unsupported."),
            _ => throw new InvalidOperationException("CurrentVersion registry access should not occur when probe is unsupported."),
            () => Architecture.X64,
            () => "Microsoft Windows 10.0.26200",
            () => 16);

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Equal("proc-files", result.ProbeId);
        Assert.Equal(ProbeOutcome.NotSupported, result.Outcome);
        Assert.Empty(result.Evidence);
    }
}