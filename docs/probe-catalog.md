# Probe Catalog

## Safe Local
- `marker-files`: `/.dockerenv`, `/run/.containerenv`
- `environment`: allowlisted markers for Docker/Kubernetes/ECS/Azure/Cloud Run/Nomad/OpenShift/IoTEdge; hostname is redacted by default
- `proc-files`:
  - `/proc/self|1/cgroup`, `/proc/self|1/mountinfo`, `/proc/net/route`, `/etc/resolv.conf`
  - `/etc/hostname`, `/proc/sys/kernel/hostname`
  - `/etc/os-release`, `/usr/lib/os-release`
  - `/proc/version`, `/proc/sys/kernel/osrelease`, `/proc/sys/kernel/ostype`, `/proc/sys/kernel/version`
  - public vendor kernel sysctls discovered conservatively under `/proc/sys/kernel/` for suffixes `*_hw_version`, `*_hw_revision`, `*_install_flag`
  - `/proc/cpuinfo`, `/sys/devices/system/cpu/{online,possible,present}`
  - `/sys/class/dmi/id/{sys_vendor,product_name,product_family,product_version,board_vendor,board_name,chassis_vendor,bios_vendor,modalias}`
  - `/proc/device-tree/{model,compatible}` and `/sys/firmware/devicetree/base/{model,compatible}` when publicly readable
  - `/sys/devices/soc0/{machine,family,soc_id,revision}` when publicly readable
  - `/sys/bus/platform/devices/*/{modalias,uevent}` for non-addressed platform devices; extracts `MODALIAS` and `OF_COMPATIBLE_*` lines
  - `/proc/meminfo`, `/sys/fs/cgroup/memory*`, `/sys/fs/cgroup/cpu*`
  - `/proc/self/ns/*`
- `security-sandbox`: `/proc/self/status` (Seccomp, NoNewPrivs, CapEff, CapBnd, CapPrm), `/proc/self/attr/current` (AppArmor/SELinux context), `/sys/fs/selinux` (SELinux mount presence)

## Runtime APIs
- `runtime-api`: probes Docker-compatible sockets and Podman Libpod endpoints (`/_ping`, `/version`, `/info`, `/libpod/*`)
- extracts safe host fields from Docker `/info` and Podman `/libpod/info`
- probes `/containers/{hostname}/json` for Docker Compose labels without exposing container IDs or host names by default

## Orchestrator / Cloud
- `kubernetes`: service account + API probes, optional pod lookup, optional node lookup for `status.nodeInfo`
- `cloud-metadata`: ECS metadata, AWS IMDSv2 safe identity document, Azure IMDS safe compute metadata, GCP machine-type/zone, OCI instance metadata, cloud env markers
