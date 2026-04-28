# Probe Catalog

## Safe Local
- `marker-files`: `/.dockerenv`, `/run/.containerenv`
- `proc-files`: `/proc/self|1/mountinfo`, `/proc/net/route`, `/etc/resolv.conf`, `/etc/hostname`, `/proc/sys/kernel/hostname`, `/etc/os-release`, `/proc/version`, `/proc/self/status`, `/proc/self/ns/*`
- `environment`: allowlisted markers for Docker/Kubernetes/ECS/Azure/Cloud Run/Nomad/OpenShift

## Runtime APIs
- `runtime-api`: probes Docker-compatible sockets and Podman Libpod endpoints (`/_ping`, `/version`, `/info`, `/libpod/*`)

## Orchestrator / Cloud
- `kubernetes`: service account + API probes
- `cloud-metadata`: ECS metadata, AWS IMDSv2 (safe document only), Azure IMDS, GCP metadata, OCI metadata, cloud env markers
