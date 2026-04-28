# Probe Catalog

## Safe Local
- `marker-files`: `/.dockerenv`, `/run/.containerenv`
- `proc-files`: `/proc/self|1/cgroup`, `/proc/self|1/mountinfo`, `/proc/net/route`, `/etc/resolv.conf`, `/etc/hostname`, `/proc/sys/kernel/hostname`, `/etc/os-release`, `/proc/version`, `/proc/self/ns/*`
- `security-sandbox`: `/proc/self/status` (Seccomp, NoNewPrivs, CapEff, CapBnd, CapPrm), `/proc/self/attr/current` (AppArmor/SELinux context), `/sys/fs/selinux` (SELinux mount presence)
- `environment`: allowlisted markers for Docker/Kubernetes/ECS/Azure/Cloud Run/Nomad/OpenShift/IoTEdge

## Runtime APIs
- `runtime-api`: probes Docker-compatible sockets and Podman Libpod endpoints (`/_ping`, `/version`, `/info`, `/libpod/*`); also probes `/containers/{hostname}/json` for Docker Compose labels

## Orchestrator / Cloud
- `kubernetes`: service account + API probes
- `cloud-metadata`: ECS metadata, AWS IMDSv2 (safe document only), Azure IMDS, GCP metadata, OCI metadata, cloud env markers
