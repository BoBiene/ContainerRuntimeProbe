/root/.nuget/packages/microsoft.build.tasks.git/8.0.0/build/Microsoft.Build.Tasks.Git.targets(25,5): warning : Repository '/workspace/ContainerRuntimeProbe' has no remote. [/workspace/ContainerRuntimeProbe/src/ContainerRuntimeProbe/ContainerRuntimeProbe.csproj]
/root/.nuget/packages/microsoft.sourcelink.common/8.0.0/build/Microsoft.SourceLink.Common.targets(53,5): warning : Source control information is not available - the generated source link is empty. [/workspace/ContainerRuntimeProbe/src/ContainerRuntimeProbe/ContainerRuntimeProbe.csproj]
/root/.nuget/packages/microsoft.build.tasks.git/8.0.0/build/Microsoft.Build.Tasks.Git.targets(25,5): warning : Repository '/workspace/ContainerRuntimeProbe' has no remote. [/workspace/ContainerRuntimeProbe/src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj]
/root/.nuget/packages/microsoft.sourcelink.common/8.0.0/build/Microsoft.SourceLink.Common.targets(53,5): warning : Source control information is not available - the generated source link is empty. [/workspace/ContainerRuntimeProbe/src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj]
# Container Runtime Report
## Summary
- IsContainerized: True (Medium)
- ContainerRuntime: Unknown (Unknown)
- RuntimeApi: Unknown (Unknown)
- Orchestrator: Unknown (Unknown)
- CloudProvider: Azure (Medium)
- PlatformVendor: Unknown (Unknown)

## Security and Limitations
- None detected by current probes.

## Raw Evidence
### marker-files (Success)
- /.dockerenv: True
- /run/.containerenv: False
### environment (Success)
- HOSTNAME: 96548146ac99
### proc-files (Success)
- /etc/hostname: 96548146ac99
- /proc/sys/kernel/hostname: 96548146ac99
- os.id: ubuntu
- os.version: 24.04
- /proc/version: Linux version 6.12.47 (@124b6677fa5a) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Mon Oct 27 10:01:15 UTC 2025
- status.CapEff: 00000000a80425fb
- status.NoNewPrivs: 0
- status.Seccomp: 0
- status.Seccomp_filters: 0
- ns.pid: pid:[4026532176]
- ns.mnt: mnt:[4026532177]
- ns.net: net:[4026531840]
- ns.uts: uts:[4026532147]
- ns.ipc: ipc:[4026532146]
### runtime-api (Unavailable)
- message: No docker/podman socket found
### kubernetes (Unavailable)
- message: Kubernetes env/token missing
### cloud-metadata (Success)
- azure.imds.outcome: AccessDenied
- gcp.metadata.outcome: AccessDenied
- oci.metadata.outcome: AccessDenied

