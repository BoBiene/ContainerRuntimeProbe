# Container Runtime Report
## Summary
- IsContainerized: True (Low)
- ContainerRuntime: Podman (Medium)
- Virtualization: None (Medium)
- HostFamily: Linux (High)
- HostType: StandardLinux (High)
- EnvironmentType: Unknown (Low)
- RuntimeApi: DockerEngineApi (Medium)
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
- Compiler: gcc-13 13.3.0
- Compiler Raw: gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1
- Compiler Distribution Hint: Unknown
- Compiler Distribution Version Hint: Unknown
- Architecture: x86_64
- Confidence: Medium

### Virtualization
- Type: Unknown
- Platform Vendor: Unknown
- Confidence: Unknown

### Underlying Host OS
- Family: Unknown
- Name: Unknown
- Version: Unknown
- Version Hint: Unknown
- Source: Unknown
- Confidence: Unknown

### Runtime-Reported Host OS
- Source: DockerInfo
- OS: Ubuntu 24.04.4 LTS
- Kernel: 6.17.0-1010-azure
- Architecture: X64
- Confidence: High

### Host Hardware Signals
- CPU: AMD EPYC 9V74 80-Core Processor, 2 logical processors
- Memory: 7,75 GB visible, cgroup limit: Unknown
- Machine Type: Unknown

### Diagnostic Fingerprints
- Algorithm: CRP-HOST-FP-v1
- Value: sha256:4ea14e1e2e254175246ddd5f0a803b70f57914c0ec4c4e3d2e92c25b64b560fb
- Stability: RuntimeApiBacked
- Included Signals: 12
- Excluded Sensitive Signals: 2
- Warning: Fingerprint is diagnostic only and not a security identity.

### Identity Anchors
- No explicit identity anchors were derived from the visible environment.

## Security and Limitations
- [DOCKER_SOCKET_MOUNTED] Docker-compatible socket is accessible and can imply privileged host control.

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
- memory.mem_available_bytes: 5527855104
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
### runtime-api (Success)
- socket.present: /var/run/docker.sock
- /var/run/docker.sock:/_ping:outcome: Success
- /var/run/docker.sock:/_ping:status: 200
- runtime.api.endpoint: /_ping
- /var/run/docker.sock:/version:outcome: Success
- /var/run/docker.sock:/version:status: 200
- runtime.engine.version: 28.0.4
- runtime.engine.api_version: 1.48
- /var/run/docker.sock:/info:outcome: Success
- /var/run/docker.sock:/info:status: 200
- docker.info.operating_system: Ubuntu 24.04.4 LTS
- docker.info.os_type: linux
- docker.info.architecture: x86_64
- docker.info.kernel_version: 6.17.0-1010-azure
- docker.info.ncpu: 2
- docker.info.mem_total: 8323989504
- docker.info.server_version: 28.0.4
- docker.info.cgroup_driver: systemd
- docker.info.cgroup_version: 2
- docker.info.default_runtime: runc
- docker.info.security_options_count: 3
- runtime.architecture: x86_64
- /var/run/docker.sock:/libpod/_ping:outcome: Unavailable
- /var/run/docker.sock:/libpod/_ping:status: 404
- /var/run/docker.sock:/libpod/version:outcome: Unavailable
- /var/run/docker.sock:/libpod/version:status: 404
- /var/run/docker.sock:/libpod/info:outcome: Unavailable
- /var/run/docker.sock:/libpod/info:status: 404
- container.inspect.outcome: Unavailable
- container.inspect.status: 404
- socket.present: /run/docker.sock
- /run/docker.sock:/_ping:outcome: Success
- /run/docker.sock:/_ping:status: 200
- runtime.api.endpoint: /_ping
- /run/docker.sock:/version:outcome: Success
- /run/docker.sock:/version:status: 200
- runtime.engine.version: 28.0.4
- runtime.engine.api_version: 1.48
- /run/docker.sock:/info:outcome: Success
- /run/docker.sock:/info:status: 200
- docker.info.operating_system: Ubuntu 24.04.4 LTS
- docker.info.os_type: linux
- docker.info.architecture: x86_64
- docker.info.kernel_version: 6.17.0-1010-azure
- docker.info.ncpu: 2
- docker.info.mem_total: 8323989504
- docker.info.server_version: 28.0.4
- docker.info.cgroup_driver: systemd
- docker.info.cgroup_version: 2
- docker.info.default_runtime: runc
- docker.info.security_options_count: 3
- runtime.architecture: x86_64
- /run/docker.sock:/libpod/_ping:outcome: Unavailable
- /run/docker.sock:/libpod/_ping:status: 404
- /run/docker.sock:/libpod/version:outcome: Unavailable
- /run/docker.sock:/libpod/version:status: 404
- /run/docker.sock:/libpod/info:outcome: Unavailable
- /run/docker.sock:/libpod/info:status: 404
- container.inspect.outcome: Unavailable
- container.inspect.status: 404
### kubernetes (Unavailable)
- message: Kubernetes env/token missing
### cloud-metadata (Success)
- azure.imds.outcome: Timeout
- gcp.metadata.machine_type.outcome: Unavailable
- gcp.metadata.zone.outcome: Unavailable
- gcp.metadata.outcome: Unavailable
- oci.metadata.outcome: Timeout
