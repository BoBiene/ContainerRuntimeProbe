# Container Runtime Report
## Summary
- IsContainerized: True (Low)
- ContainerRuntime: Unknown (Unknown)
- RuntimeApi: Unknown (Unknown)
- Orchestrator: Unknown (Unknown)
- CloudProvider: Unknown (Unknown)
- PlatformVendor: Unknown (Unknown)

## Host OS / Node
### Container Image OS
- Family: Ubuntu
- ID: ubuntu
- Version: 24.04.4 LTS (Noble Numbat)
- Pretty Name: Ubuntu 24.04.4 LTS
- Architecture: X64
- Confidence: High

### Visible Kernel
- Name: Linux
- Release: 6.17.0-1010-azure
- Flavor: Azure
- Architecture: x86_64
- Confidence: Medium

### Runtime-Reported Host OS
- Source: Unknown
- OS: Unknown
- Kernel: Unknown
- Architecture: Unknown
- Confidence: Unknown

### Host Hardware Signals
- CPU: AMD EPYC 9V74 80-Core Processor, 2 logical processors
- Memory: 7.75 GB visible, cgroup limit: Unknown
- Machine Type: Unknown

### Host Fingerprint
- Algorithm: CRP-HOST-FP-v1
- Value: sha256:6813124e32d17aa8a06b66e1a8417b2ae389c100c021906b7a3ff48a2b62a5a3
- Stability: KernelOnly
- Included Signals: 8
- Excluded Sensitive Signals: 1
- Warning: Fingerprint is diagnostic only and not a security identity.

## Security and Limitations
- None detected by current probes.

## Raw Evidence
### marker-files (Success)
- /.dockerenv: False
- /run/.containerenv: False
### environment (Success)
### proc-files (Success)
- /proc/self/mountinfo:signal: overlay
- /proc/1/mountinfo:signal: overlay
- default-route-device: eth0
- dns-search: vcq0jmfdokweppwtd0ncfytsif.dx.internal.cloudapp.net
- /etc/hostname: redacted
- /proc/sys/kernel/hostname: redacted
- os.id: ubuntu
- os.id_like: debian
- os.name: Ubuntu
- os.pretty_name: Ubuntu 24.04.4 LTS
- os.version: 24.04.4 LTS (Noble Numbat)
- os.version_id: 24.04
- os.version_codename: noble
- os.home_url: https://www.ubuntu.com/
- os.support_url: https://help.ubuntu.com/
- os.bug_report_url: https://bugs.launchpad.net/ubuntu/
- /proc/version: Linux version 6.17.0-1010-azure (buildd@lcy02-amd64-097) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #10~24.04.1-Ubuntu SMP Fri Mar  6 22:00:57 UTC 2026
- kernel.release: 6.17.0-1010-azure
- kernel.name: Linux
- kernel.version: #10~24.04.1-Ubuntu SMP Fri Mar  6 22:00:57 UTC 2026
- cpu.logical_processors: 2
- cpu.vendor: AuthenticAMD
- cpu.model_name: AMD EPYC 9V74 80-Core Processor
- cpu.family: 25
- cpu.model: 17
- cpu.stepping: 1
- cpu.microcode: 0xffffffff
- cpu.flags.count: 116
- cpu.flags.hash: sha256:b91b163d336e110f324f7ec36aa576a99ed4fa6a9e23b4a9af1c39515243a72c
- cpu.online: 0-1
- cpu.online.count: 2
- cpu.possible: 0-1
- cpu.possible.count: 2
- cpu.present: 0-1
- cpu.present.count: 2
- memory.mem_total_bytes: 8323989504
- memory.mem_available_bytes: 5530607616
- /sys/fs/cgroup/memory.max: Unavailable
- /sys/fs/cgroup/memory.current: Unavailable
- /sys/fs/cgroup/memory/memory.limit_in_bytes: Unavailable
- /sys/fs/cgroup/memory/memory.usage_in_bytes: Unavailable
- /sys/fs/cgroup/cpu.max: Unavailable
- /sys/fs/cgroup/cpu/cpu.cfs_quota_us: Unavailable
- ns.pid: pid:[4026531836]
- ns.mnt: mnt:[4026531832]
- ns.net: net:[4026531833]
- ns.uts: uts:[4026531838]
- ns.ipc: ipc:[4026531839]
- kernel.name: Linux
- kernel.release: 6.17.0-1010-azure
- kernel.version: #10~24.04.1-Ubuntu SMP Fri Mar  6 22:00:57 UTC 2026
- kernel.compiler: gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1
- kernel.flavor: Azure
### security-sandbox (Success)
- proc.self.status.outcome: Success
- status.CapPrm: 0000000000000000
- status.CapEff: 0000000000000000
- status.CapBnd: 000001ffffffffff
- status.NoNewPrivs: 0
- status.Seccomp: 0
- status.Seccomp: 0
- apparmor.profile: unconfined
- selinux.mount.present: False
### kubernetes (Unavailable)
- message: Kubernetes env/token missing
### cloud-metadata (Success)
- azure.imds.outcome: Timeout
- gcp.metadata.machine_type.outcome: Unavailable
- gcp.metadata.zone.outcome: Unavailable
- gcp.metadata.outcome: Unavailable
- oci.metadata.outcome: Timeout

