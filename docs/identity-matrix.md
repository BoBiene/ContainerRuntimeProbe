# Identity Matrix

This document describes which observed signals can become which identity, how summary levels map to anchor strength, and where the current code still has intentional gaps.

## Working definitions

- Host: the physical system or VM guest OS instance that owns the visible kernel and hardware profile.
- Container: the current application container instance.
- Environment: the surrounding platform boundary such as a Kubernetes cluster, cloud environment, Compose project, or Siemens runtime environment.
- Hypervisor: the virtualization substrate below the visible host OS.

All identities remain read-only observed digests. Heuristic profiles stay diagnostic fingerprints unless explicitly promoted to an identity anchor.

## Level rules

| Level | Meaning | Typical source shape | Allowed usage |
| --- | --- | --- | --- |
| L1 | Weak correlation only | restart-sensitive instance tuple or public host-profile digest | Correlation |
| L2 | Medium anchor | explicit local install/runtime ID that is stable but clone/recreate/reinstall sensitive | Correlation, soft binding |
| L3 | Strong anchor | explicit provider/platform identity or cryptographically rooted runtime identity | Binding candidate |
| L4 | Corroborated strong anchor | L3 anchor plus independent trusted-platform verification | Strong binding candidate |

Current summary mapping is:

- `IdentityAnchorStrength.Weak` -> `L1`
- `IdentityAnchorStrength.Medium` -> `L2`
- `IdentityAnchorStrength.Strong` -> `L3`
- trusted-platform corroboration may raise selected platform anchors to `L4`

## Current shipped matrix

| Target ID | Source | Probe / evidence | Scope | Level today | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Host | Cloud instance ID | `cloud-metadata`: `aws.instance_id`, `azure.vm_id`, `gcp.instance_id`, `oci.instance_id` | Host | L3 | Implemented | Best current host anchor when IMDS is reachable from the workload. |
| Host | Kubernetes node UID | `kubernetes`: `kubernetes.node.uid` | Host | L3 | Implemented | Strong node/host identity when Node API metadata is visible. |
| Host | Kubernetes node provider ID | `kubernetes`: `kubernetes.node.provider_id` | Host | L2 | Implemented | Medium fallback when UID is unavailable but provider ID is visible. |
| Host | Windows MachineGuid | `proc-files`: `windows.machine_guid` | Host | L2 | Implemented | Only outside containerized classifications. Conservative host-correlation anchor. |
| Host | Linux machine-id | `proc-files`: `machine.id` | Host | L2 | Implemented | Only outside containerized classifications. Conservative host-correlation anchor. |
| Host | TPM public-material digest | `proc-files`: `device.tpm.ek_cert.sha256`, `device.tpm.pubek.sha256` | Host | L3 | Implemented | Strong host anchor when read-only TPM public material is visible through the local Linux TPM sysfs path. |
| Host | Explicit hardware identifiers | `proc-files`: `dmi.product_uuid`, `dmi.product_serial`, `dmi.board_serial`, `dmi.chassis_serial`, `device_tree.serial_number`, `soc.serial_number`, `cpu.serial` | Host | L2 | Implemented | Conservative host anchor from directly visible hardware-bound identifiers. |
| Host | Public host-profile digest | visible kernel, CPU family/model, memory bucket, DMI or device-tree product hints, virtualization/modalias hints | Host | L1 | Implemented | Weak host-correlation fallback when no explicit host-bound identifier is visible. |
| Container | Runtime inspect container ID | `runtime-api`: `container.id` | Workload | L2 | Implemented | Good application-container-instance identity when a socket-backed inspect path is readable. |
| Container | Kubernetes pod/container workload tokens | `kubernetes`: `kubernetes.pod.uid`; `proc-files`: `kubernetes.cgroup.pod_uid`, `kubernetes.cgroup.container_token` | Workload | L2 with container token, else L1 | Implemented | Better Kubernetes-specific workload identity when runtime inspect is unavailable. |
| Container | Namespace tuple | `proc-files`: `ns.pid`, `ns.mnt`, `ns.net` | Workload | L1 | Implemented | Weak fallback when no runtime inspect ID is visible. Restart and reschedule sensitive. |
| Environment | Diagnostic deployment/environment fingerprint | `Host.DiagnosticFingerprints[]` | Deployment / Platform | L1 | Implemented | Shown as `Deployment ID` for standalone containers and `Environment ID` for Kubernetes or industrial variants. Diagnostic only. |
| Environment | Kubernetes service-account CA bundle digest | `kubernetes`: `serviceaccount.ca.sha256` | Platform | L2 | Implemented | Conservative cluster/environment identity that works without Pod or Node RBAC. |
| Environment | Compose / Portainer deployment metadata | `runtime-api`: `compose.label.com.docker.compose.project`, `compose.label.com.docker.stack.namespace`, `compose.label.io.portainer.*` | Deployment / Platform | L2 | Implemented | Stronger deployment/environment identity when socket-backed inspect exposes project or stack metadata. |
| Environment | Cloud account / subscription / project / compartment metadata | `cloud-metadata`: `aws.account_id`, `azure.subscription_id`, `gcp.project_id`, `oci.compartment_id` | Platform | L2 | Implemented | Conservative cloud-environment identity for the provider boundary, separate from the individual host instance ID. |
| Environment | Siemens IED TLS-bound runtime identity | `siemens-ied-runtime`: `trust.ied.certsips.cert_chain_sha256` + `trust.ied.endpoint.tls.binding=matched` | Platform | L3 | Implemented | Current strongest non-cloud environment/platform identity. |
| Environment | Siemens IED trusted verification | `TrustedPlatforms[siemens-ied-runtime]` | Platform | L4 | Implemented | Raises the summary level when the local trust path is corroborated. |
| Hypervisor | Guest-visible VM UUID | `proc-files`: `dmi.product_uuid` when virtualization is classified | Hypervisor | L2 | Implemented | Conservative hypervisor or guest-substrate identity derived from guest-visible VM UUIDs under an observed virtualized runtime. |

## Candidate source matrix

These are the realistic next candidates if the goal is at least one `Host` L1 everywhere, one `Container` ID in containers, one `Environment` ID where applicable, and ideally one `Hypervisor` ID.

| Candidate raw source | Likely systems | Probe surface | Intended target | Proposed level if used alone | Proposed level when corroborated | Why it matters |
| --- | --- | --- | --- | --- | --- | --- |
| SMBIOS UUID or serials such as `product_uuid`, `product_serial`, `board_serial`, `chassis_serial` | Linux hosts, many VMs, some containers with readable `/sys/class/dmi/id/*` | `proc-files` raw evidence | Host | L2 | L3 with cloud/node/trust corroboration | Better host uniqueness than public vendor strings. Now promoted into a conservative host anchor when visible. |
| CPU serial | ARM SBCs, industrial ARM, some embedded Linux | existing `proc-files` can already emit `cpu.serial` when visible | Host | L2 | L3 with corroboration | Often absent on x86, but strong on some appliance and SBC targets. Now promoted into a conservative host anchor when visible. |
| Device-tree serial number or SoC unique serial | ARM appliances, embedded boards | `proc-files` raw evidence under device-tree / SoC | Host | L2 | L3 with corroboration | Important for industrial or edge hardware where DMI is absent but SoC identity exists. Now promoted into a conservative host anchor when visible. |
| Public host-profile digest built from kernel, CPU, memory bucket, DMI vendor/product, virtualization, and platform modalias families | Generic containers with no explicit stable host ID | existing `proc-files`, `runtime-api`, classification | Host | L1 | stays L1 unless paired with explicit host ID | This is now promoted when no explicit host anchor is visible, but it remains a weak host-correlation profile rather than a strong physical-host identity. |
| Pod UID or cgroup-derived pod/container token | Kubernetes workloads | existing cgroup parsing and optional pod metadata today | Container | L1 or L2 | L2 with runtime container ID or pod metadata | Kubernetes workload tokens are now promoted when visible, with pod-scoped fallbacks kept weaker than per-container tokens. |
| Compose / Portainer project labels | Docker Compose, Portainer | existing `runtime-api` compose label extraction | Environment / Deployment | L2 | L2 | These labels are now promoted when visible through socket-backed inspect metadata. |
| Kubernetes control-plane CA bundle digest or API server SPKI digest | Kubernetes, including no-RBAC service-account cases | service-account CA material today; API certificate material later if needed | Environment | L2 | L3 with API identity corroboration | The service-account CA digest is now promoted; API certificate material remains a future corroboration path. |
| Cloud tenant / project / subscription digest | Cloud-managed environments | cloud metadata normalization where visible | Environment | L2 | L2 or L3 depending on provider certainty | Now promoted from visible AWS/Azure/GCP/OCI provider-boundary metadata. |
| TPM public material digest such as EK pubkey or persistent public key digest | Windows hosts, Linux with visible TPM, some appliance systems | read-only Linux TPM sysfs public material today; broader TPM retrieval later if needed | Host or Platform | L3 | L4 with trusted verification | Linux TPM public material is now promoted when visible; stronger corroboration and broader platform coverage remain future work. |
| VM UUID / generation ID / guest-visible hypervisor instance UUID | Hyper-V, VMware, Xen, KVM guests | guest-visible VM UUID from DMI today; more explicit generation-ID probes later if needed | Hypervisor | L2 | L3 with corroboration | Guest-visible VM UUIDs are now promoted when virtualization is classified; explicit generation-ID sources remain a future refinement. |

## System-by-system matrix

| Situation | Main visible probes today | Host ID today | Container ID today | Environment ID today | Hypervisor ID today | Best next candidate |
| --- | --- | --- | --- | --- | --- | --- |
| Windows host process | `windows.machine_guid`, Windows BIOS registry, Windows CPU registry, memory API | L2 via `MachineGuid` | n/a | none | none | TPM public material for Host L3/L4 |
| Linux host process | `machine.id`, CPU, memory, DMI, device-tree, virtualization files | L2 via `machine.id` | n/a | none | none | SMBIOS UUID/serial or TPM public material |
| Generic Docker/Podman container on native Linux | CPU, memory, DMI when visible, namespace tuple, optional runtime inspect | L1 via host-profile digest, or L2 via explicit hardware IDs when visible | L2 via `container.id`, else L1 via namespace tuple | L2 via Compose or Portainer metadata when visible, else L1 `Deployment ID` | none | none for deployment identity; hypervisor remains separate |
| Container on WSL2 / Hyper-V | CPU, memory, `cpu.flag.hypervisor`, `bus.vmbus.present`, `platform.modalias`, namespace tuple | L1 via weak host-profile digest unless stronger host IDs become visible | L2 via `container.id`, else L1 via namespace tuple | L2 via Compose or Portainer metadata when visible, else L1 `Deployment ID` | none, only vendor classification | Hypervisor L2 via VM generation/UUID |
| Kubernetes workload without RBAC to read Pod/Node | service-account env, CA bundle digest, cgroup workload token, namespace tuple, kernel/hardware profile | L1 via weak host-profile digest when enough coarse host signals are visible | L2 via Kubernetes cgroup container token when visible, else L1 via namespace tuple | L2 via cluster CA digest | none | none for environment; future API certificate corroboration could raise confidence |
| Kubernetes workload with readable Pod/Node metadata | Kubernetes API metadata, service-account CA digest, pod UID, optional node UID/provider ID, cgroup workload token, namespace tuple | L3 via node UID or L2 via provider ID | L2 via pod UID plus cgroup container token when visible, else L1 or L2 depending on workload source | L2 via cluster CA digest | none | Future cluster UID or API-certificate corroboration |
| Cloud VM container with reachable IMDS | cloud instance metadata, cloud account/project/subscription/compartment metadata, cloud region, machine type, namespace tuple | L3 via cloud instance ID | L1 or L2 depending on runtime visibility | L2 via cloud provider boundary digest when visible | none | Provider-specific corroboration if stronger environment certainty is ever needed |
| Siemens IED runtime | documented runtime artifact, TLS binding, optional endpoint verification | host depends on separate host signals | workload depends on separate container signals | L3 or L4 platform/environment identity | none | none needed for environment; host still needs separate signals |

## Local reality check from the current Podman and kind artifacts

The local Podman and kind captures in `artifacts/` currently show:

- visible namespace tuples: `ns.pid`, `ns.mnt`, `ns.net`
- visible virtualization indicators: `cpu.flag.hypervisor`, `bus.vmbus.present`, `platform.modalias` with Microsoft / VMBus fragments
- `/sys/hypervisor/type` was not useful in the sampled Podman and kind runs
- no visible `machine.id`
- no visible `windows.machine_guid`
- no visible DMI serial/UUID fields in the sampled local Podman and kind reports
- no visible `cpu.serial` in the sampled local Podman and kind runs

That means the current local container samples are enough for:

- `Host` L1 via weak host-profile digest
- `Container` L1 everywhere via namespace tuples
- `Environment` L1 in Kubernetes and standalone container summaries
- hypervisor or WSL2 vendor classification

They are still not enough for a stronger `Host` L2/L3 anchor under the current strict semantics, because the visible local signals are host-adjacent profile hints, not an explicit host-bound identifier.

## Practical recommendation

If the product goal is truly "at least one Host L1 in every situation", there are two viable paths:

1. Add a weak `Host` fallback from a public host-profile digest and explicitly document that this is only correlation-grade and may collide across similar hosts.
2. Add stronger read-only host-bound raw sources first: SMBIOS UUID/serials, device-tree or SoC serials, CPU serial where available, and optionally TPM public material digests.

For Kubernetes without RBAC, the best environment upgrade path is a digest over the visible control-plane CA bundle or API server SPKI, because that respects the requirement to work only with what is already visible.

For TPM-backed host identity, the current read-only path is a digest over visible TPM public material such as Linux `ek_cert` or `pubek` sysfs artifacts when those files are exposed to the current process.

For cloud-managed environments with reachable provider metadata, the current conservative environment path is a digest over the visible provider boundary identifier such as AWS account, Azure subscription, GCP project, or OCI compartment metadata.

For hypervisors, the current conservative path is a digest over a guest-visible VM UUID when virtualization is already classified. Future refinement should add more explicit generation-ID style sources where they are available.