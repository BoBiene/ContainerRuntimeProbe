# Probe Catalog

## Safe Local
- `marker-files`: `/.dockerenv`, `/run/.containerenv`
- `environment`: allowlisted markers for Docker/Kubernetes/ECS/Azure/Cloud Run/Nomad/OpenShift/IoTEdge; hostname is redacted by default
- `platform-context`:
  - bounded Siemens/Industrial Edge context signals from env keys and values, `/proc/self|1/mountinfo`, `/proc/self|1/cgroup`, `/etc/hostname`, `/proc/sys/kernel/hostname`, `HOSTNAME`, and `/etc/resolv.conf`
  - normalizes only targeted platform hints such as `siemens`, `industrial-edge`, `industrialedge`, `iotedge`, `iem`, and `ied`; generic `edge` substrings are ignored
- `siemens-ied-runtime`:
  - collects documented IED trust artifacts from `/var/run/devicemodel/edgedevice/certsips.json`
  - when `certsips.json` is structurally plausible, it also attempts a bounded local HTTPS check to the documented auth endpoint and records TLS binding evidence against documented certificate material
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
- `windows-trust`:
  - bounded Windows TPM presence via the local Trusted Base Services API (`tbs.dll`)
  - records only normalized TPM device facts such as outcome, TPM version, interface type, and implementation revision
  - does not perform remote attestation, quote validation, or container binding on its own
- `security-sandbox`: `/proc/self/status` (Seccomp, NoNewPrivs, CapEff, CapBnd, CapPrm), `/proc/self/attr/current` (AppArmor/SELinux context), `/sys/fs/selinux` (SELinux mount presence)

## Runtime APIs
- `runtime-api`: probes Docker-compatible sockets and Podman Libpod endpoints (`/_ping`, `/version`, `/info`, `/libpod/*`)
- extracts safe host fields from Docker `/info` and Podman `/libpod/info`
- probes `/containers/{hostname}/json` for Docker Compose labels without exposing container IDs or host names by default

## Trusted Platform Notes
- `siemens-ied-runtime` is the current Siemens-specific trust source for `TrustedPlatforms`.
- `windows-trust` is a second trust source for `TrustedPlatforms`, currently limited to local Windows TPM device presence and plausibility.
- explicit TPM device-node visibility from `proc-files` is a third trust source for `TrustedPlatforms`, currently limited to observed container-visible device nodes such as `/dev/tpm0`, `/dev/tpmrm0`, and `/dev/vtpmx`.
- General env, hostname, DNS, mount, and cgroup string hits stay heuristic and can contribute to `PlatformEvidence`, but they never become trusted claims on their own.
- Current trusted scope remains intentionally narrow: `siemens-ied-runtime`, conservative `windows-host-tpm`, and observational `container-tpm-visible`. There is still no trusted `siemens-iem`, no license/entitlement claim, and no TPM quote or hardware attestation flow in this step.

## Identity Anchor Notes
- `IdentityAnchors` are separate from `TrustedPlatforms` and are built from explicit observed IDs rather than heuristic strings.
- Current built-in anchors are `CloudInstanceIdentity` from AWS/Azure/GCP/OCI instance metadata IDs, `KubernetesNodeIdentity` from Kubernetes node UID or provider ID, and `VendorRuntimeIdentity` from Siemens IED certificate-chain evidence when the documented local TLS binding is matched.
- Weak generic signals such as hostname, DNS labels, mount paths, cgroup strings, or visible TPM device nodes do not become license-binding anchors on their own.
- Anchor values are stored as digests and are redacted in the default host report.
- Future TPM or machine-certificate anchors must stay read-only and digest-based; the package must not create TPM keys or provision certificates.

## Orchestrator / Cloud
- `kubernetes`: service account + API probes, optional pod lookup, optional node lookup for `status.nodeInfo`, `metadata.uid`, and `spec.providerID`
- `cloud-metadata`: ECS metadata, AWS IMDSv2 safe identity document, Azure IMDS safe compute metadata, GCP machine-type/zone/instance-id, OCI instance metadata, cloud env markers
