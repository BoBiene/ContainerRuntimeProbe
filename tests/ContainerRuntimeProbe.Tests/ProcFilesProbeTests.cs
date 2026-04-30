using System.Threading;
using System.Runtime.InteropServices;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Probes;

namespace ContainerRuntimeProbe.Tests;

public sealed class ProcFilesProbeTests
{
    [Fact]
    public async Task ProcFilesProbe_StartsReadsConcurrently_WhilePreservingFileProcessing()
    {
        var allStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var startedCount = 0;
        var probe = new ProcFilesProbe(
            ["/proc/version", "/proc/sys/kernel/osrelease"],
            async (_, _, cancellationToken) =>
            {
                if (Interlocked.Increment(ref startedCount) == 2)
                {
                    allStarted.TrySetResult(true);
                }

                await allStarted.Task.WaitAsync(TimeSpan.FromSeconds(1), cancellationToken);
                return (ProbeOutcome.Unavailable, null, (string?)null);
            });

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Equal("proc-files", result.ProbeId);
        Assert.Contains(result.Evidence, item => item.Key == "/proc/version" && item.Value == ProbeOutcome.Unavailable.ToString());
        Assert.Contains(result.Evidence, item => item.Key == "/proc/sys/kernel/osrelease" && item.Value == ProbeOutcome.Unavailable.ToString());
    }

    [Fact]
    public async Task ProcFilesProbe_ExtractsSynologyKernelAndDmiSignals()
    {
        var values = new Dictionary<string, string>
        {
            ["/proc/version"] = "Linux version 5.10.55+ (root@build7) #86009 SMP",
            ["/proc/sys/kernel/osrelease"] = "5.10.55+\n",
            ["/proc/sys/kernel/ostype"] = "Linux\n",
            ["/proc/sys/kernel/version"] = "#86009 SMP Wed Nov 26 18:45:22 CST 2025\n",
            ["/proc/sys/kernel/syno_hw_version"] = "DS925+\n",
            ["/proc/sys/kernel/syno_install_flag"] = "0\n",
            ["/sys/class/dmi/id/sys_vendor"] = "Synology Inc.\n",
            ["/sys/class/dmi/id/product_name"] = "DS925+\n",
            ["/sys/class/dmi/id/modalias"] = "dmi:bvnInsydeCorp.:svnSynologyInc.:pnDS925+:pvr1:\n"
        };

        var probe = new ProcFilesProbe(values.Keys.ToArray(), (path, _, _) =>
            Task.FromResult(values.TryGetValue(path, out var value)
                ? (ProbeOutcome.Success, (string?)value, (string?)null)
                : (ProbeOutcome.Unavailable, (string?)null, (string?)null)));

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Contains(result.Evidence, item => item.Key == "kernel.syno_hw_version" && item.Value == "DS925+");
        Assert.Contains(result.Evidence, item => item.Key == "kernel.syno_install_flag" && item.Value == "0");
        Assert.Contains(result.Evidence, item => item.Key == "dmi.sys_vendor" && item.Value == "Synology Inc.");
        Assert.Contains(result.Evidence, item => item.Key == "dmi.product_name" && item.Value == "DS925+");
        Assert.Contains(result.Evidence, item => item.Key == "dmi.modalias" && item.Value!.Contains("svnSynologyInc.", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ProcFilesProbe_DiscoversPublicKernelSysctls_AndSkipsOtherNames()
    {
        var values = new Dictionary<string, string>
        {
            ["/proc/sys/kernel/syno_hw_version"] = "DS925+\n",
            ["/proc/sys/kernel/syno_hw_revision"] = "rev1\n",
            ["/proc/sys/kernel/syno_install_flag"] = "0\n"
        };

        var probe = new ProcFilesProbe(
            [],
            (path, _, _) => Task.FromResult(values.TryGetValue(path, out var value)
                ? (ProbeOutcome.Success, (string?)value, (string?)null)
                : (ProbeOutcome.Unavailable, (string?)null, (string?)null)),
            path => path == "/proc/sys/kernel"
                ? [
                    "/proc/sys/kernel/syno_hw_version",
                    "/proc/sys/kernel/syno_hw_revision",
                    "/proc/sys/kernel/syno_install_flag",
                    "/proc/sys/kernel/syno_serial",
                    "/proc/sys/kernel/randomize_va_space"
                ]
                : []);

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Contains(result.Evidence, item => item.Key == "kernel.syno_hw_version" && item.Value == "DS925+");
        Assert.Contains(result.Evidence, item => item.Key == "kernel.syno_hw_revision" && item.Value == "rev1");
        Assert.Contains(result.Evidence, item => item.Key == "kernel.syno_install_flag" && item.Value == "0");
        Assert.DoesNotContain(result.Evidence, item => item.Key == "kernel.syno_serial");
        Assert.DoesNotContain(result.Evidence, item => item.Key == "kernel.randomize_va_space");
        Assert.Contains(result.Evidence, item => item.Key == "kernel.architecture" && item.Value == NormalizeArchitectureRaw(RuntimeInformation.OSArchitecture));
    }

    [Fact]
    public async Task ProcFilesProbe_KernelHostname_RemainsSensitiveWhenDiscoveredThroughGenericSysctlBranch()
    {
        var values = new Dictionary<string, string>
        {
            ["/proc/sys/kernel/hostname"] = "edge-host-01\n"
        };

        var probe = new ProcFilesProbe(
            values.Keys.ToArray(),
            (path, _, _) => Task.FromResult(values.TryGetValue(path, out var value)
                ? (ProbeOutcome.Success, (string?)value, (string?)null)
                : (ProbeOutcome.Unavailable, (string?)null, (string?)null)));

        var redactedContext = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var redactedResult = await probe.ExecuteAsync(redactedContext);
        Assert.Contains(redactedResult.Evidence, item => item.Key == "kernel.hostname" && item.Value == "redacted" && item.Sensitivity == EvidenceSensitivity.Sensitive);

        var sensitiveContext = new ProbeContext(TimeSpan.FromSeconds(1), true, null, null, null, null, null, null, CancellationToken.None);
        var sensitiveResult = await probe.ExecuteAsync(sensitiveContext);
        Assert.Contains(sensitiveResult.Evidence, item => item.Key == "kernel.hostname" && item.Value == "edge-host-01" && item.Sensitivity == EvidenceSensitivity.Sensitive);
    }

    [Fact]
    public async Task ProcFilesProbe_ExtractsExtendedDmiAndDeviceTreeSignals()
    {
        var values = new Dictionary<string, string>
        {
            ["/sys/class/dmi/id/product_family"] = "CX\n",
            ["/sys/class/dmi/id/chassis_vendor"] = "Beckhoff Automation\n",
            ["/proc/device-tree/model"] = "WAGO CC100\0",
            ["/proc/device-tree/compatible"] = "wago,cc100\0fsl,imx6ul\0"
        };

        var probe = new ProcFilesProbe(values.Keys.ToArray(), (path, _, _) =>
            Task.FromResult(values.TryGetValue(path, out var value)
                ? (ProbeOutcome.Success, (string?)value, (string?)null)
                : (ProbeOutcome.Unavailable, (string?)null, (string?)null)));

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Contains(result.Evidence, item => item.Key == "dmi.product_family" && item.Value == "CX");
        Assert.Contains(result.Evidence, item => item.Key == "dmi.chassis_vendor" && item.Value == "Beckhoff Automation");
        Assert.Contains(result.Evidence, item => item.Key == "device_tree.model" && item.Value == "WAGO CC100");
        Assert.Contains(result.Evidence, item => item.Key == "device_tree.compatible" && item.Value == "wago,cc100, fsl,imx6ul");
    }

    [Fact]
    public async Task ProcFilesProbe_ExtractsSocSignals()
    {
        var values = new Dictionary<string, string>
        {
            ["/sys/devices/soc0/machine"] = "WAGO CC100\n",
            ["/sys/devices/soc0/family"] = "Freescale i.MX\n",
            ["/sys/devices/soc0/soc_id"] = "i.MX6UL\n",
            ["/sys/devices/soc0/revision"] = "1.2\n"
        };

        var probe = new ProcFilesProbe(values.Keys.ToArray(), (path, _, _) =>
            Task.FromResult(values.TryGetValue(path, out var value)
                ? (ProbeOutcome.Success, (string?)value, (string?)null)
                : (ProbeOutcome.Unavailable, (string?)null, (string?)null)));

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Contains(result.Evidence, item => item.Key == "soc.machine" && item.Value == "WAGO CC100");
        Assert.Contains(result.Evidence, item => item.Key == "soc.family" && item.Value == "Freescale i.MX");
        Assert.Contains(result.Evidence, item => item.Key == "soc.soc_id" && item.Value == "i.MX6UL");
        Assert.Contains(result.Evidence, item => item.Key == "soc.revision" && item.Value == "1.2");
    }

    [Fact]
    public async Task ProcFilesProbe_DiscoversAndExtractsPlatformMetadataSignals()
    {
        var values = new Dictionary<string, string>
        {
            ["/sys/bus/platform/devices/wsysinit_init/modalias"] = "of:Nwsysinit_initT(null)Cwago,sysinit\n",
            ["/sys/bus/platform/devices/wsysinit_init/uevent"] = "OF_COMPATIBLE_0=wago,sysinit\nMODALIAS=of:Nwsysinit_initT(null)Cwago,sysinit\n"
        };

        var probe = new ProcFilesProbe(
            [],
            (path, _, _) => Task.FromResult(values.TryGetValue(path, out var value)
                ? (ProbeOutcome.Success, (string?)value, (string?)null)
                : (ProbeOutcome.Unavailable, (string?)null, (string?)null)),
            enumerateFiles: path => path == "/proc/sys/kernel" ? [] : [],
            enumerateEntries: path => path == "/sys/bus/platform/devices"
                ? ["/sys/bus/platform/devices/wsysinit_init", "/sys/bus/platform/devices/10050000.sram"]
                : []);

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Contains(result.Evidence, item => item.Key == "platform.of_compatible" && item.Value == "wago,sysinit");
        Assert.Contains(result.Evidence, item => item.Key == "platform.modalias" && item.Value == "of:Nwsysinit_initT(null)Cwago,sysinit");
    }

    [Fact]
    public async Task ProcFilesProbe_ExtractsVirtualizationSignals()
    {
        var values = new Dictionary<string, string>
        {
            ["/proc/cpuinfo"] = "processor : 0\nflags : fpu hypervisor vmx\n",
            ["/proc/modules"] = "hv_vmbus 16384 0 - Live 0x00000000\nvmxnet3 16384 0 - Live 0x00000000\nvboxguest 16384 0 - Live 0x00000000\nxen_evtchn 16384 0 - Live 0x00000000\n",
            ["/sys/hypervisor/type"] = "xen\n"
        };

        var probe = new ProcFilesProbe(
            values.Keys.ToArray(),
            (path, _, _) => Task.FromResult(values.TryGetValue(path, out var value)
                ? (ProbeOutcome.Success, (string?)value, (string?)null)
                : (ProbeOutcome.Unavailable, (string?)null, (string?)null)),
            directoryExists: path => path == "/sys/bus/vmbus/devices");

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Contains(result.Evidence, item => item.Key == "cpu.flag.hypervisor" && item.Value == bool.TrueString);
        Assert.Contains(result.Evidence, item => item.Key == "module.hv_vmbus.loaded" && item.Value == bool.TrueString);
        Assert.Contains(result.Evidence, item => item.Key == "module.vmxnet3.loaded" && item.Value == bool.TrueString);
        Assert.Contains(result.Evidence, item => item.Key == "module.vboxguest.loaded" && item.Value == bool.TrueString);
        Assert.Contains(result.Evidence, item => item.Key == "module.xen_evtchn.loaded" && item.Value == bool.TrueString);
        Assert.Contains(result.Evidence, item => item.Key == "sys.hypervisor.type" && item.Value == "xen");
        Assert.Contains(result.Evidence, item => item.Key == "bus.vmbus.present" && item.Value == bool.TrueString);
    }

    private static string NormalizeArchitectureRaw(Architecture architecture)
        => architecture switch
        {
            Architecture.X64 => "x86_64",
            Architecture.X86 => "x86",
            Architecture.Arm64 => "arm64",
            Architecture.Arm => "arm",
            Architecture.S390x => "s390x",
            _ => architecture.ToString().ToLowerInvariant()
        };
}