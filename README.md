# Container Runtime Probe

Container Runtime Probe collects runtime evidence from inside containers and helps classify the visible environment: Docker, Docker Compose, Portainer stacks, Kubernetes, WSL2, Linux hosts, NAS/appliance hosts, cloud environments, and other edge cases.

The main goal is to build a broad sample collection of real-world container environments. Each report helps improve detection quality and documents how containers look from the inside on different platforms.

## What this project is

Container Runtime Probe is both:

- a diagnostic tool that inspects the environment visible from inside a container
- a sample collection project that improves by gathering reports from many different runtimes and hosts

The project is most useful when people run it in environments that behave differently: local developer machines, NAS devices, appliance hosts, cloud VMs, managed Kubernetes clusters, homelabs, CI runners, and older systems.

## Why sample collection matters

Container environments often look similar at first glance but differ in important ways:

- Docker on native Linux does not look the same as Docker Desktop on Windows with WSL2
- Docker Compose and Portainer stacks add orchestration hints that standalone containers do not
- Kubernetes distributions expose different signals depending on cluster type and permissions
- NAS, appliance, and vendor kernels can look very different from standard Linux hosts

Broad real-world samples help improve classification rules, reduce false assumptions, and document edge cases that do not appear in clean lab environments.

## What is collected

The probe collects runtime evidence that helps classify the container environment, including:

- runtime and orchestrator signals
- kernel and distribution markers visible from inside the container
- cgroup, namespace, mount, and networking hints
- safe cloud or platform metadata outcomes when available
- redacted summary data that can be shared for issue-based sample submission

Reports help improve detection of:

- Container runtime: Docker, containerd, Podman, unknown
- Orchestrator: Kubernetes, Docker Compose, standalone Docker
- Kernel substrate: WSL2, standard Linux, appliance/vendor Linux
- Host type: cloud, on-prem, NAS/appliance, developer workstation
- Special cases: old kernels, kernel/userspace mismatch, limited cgroup visibility

## Privacy and redaction

Generated issue content applies built-in redaction for known sensitive fields, but manual review is still required.

The tool should redact sensitive values such as hostnames where possible. Review the generated issue body before submitting. Do not submit private secrets, tokens, internal URLs, or customer-identifying information.

If you share a full JSON report, inspect it first and remove anything you do not want to publish.

## Quick submit samples

The default issue target is this repository: `BoBiene/ContainerRuntimeProbe`. You only need `--repo` if you want to submit somewhere else.

### Docker

Run the probe:

```bash
docker run --pull=always --rm ghcr.io/bobiene/containerruntimeprobe:preview
```

Published container images target `linux/amd64`, `linux/arm64`, and `linux/arm/v7`.
`linux/arm64` Native AOT is only enabled when the image is built on a real arm64 runner; standard CI builds publish arm64 as a trimmed self-contained binary instead. `linux/386` is not currently published.

Generate only the prefilled GitHub issue URL:

```bash
docker run --pull=always --rm ghcr.io/bobiene/containerruntimeprobe:preview sample --url-only
```

Open the generated URL on Linux:

```bash
docker run --pull=always --rm ghcr.io/bobiene/containerruntimeprobe:preview sample --url-only | xargs xdg-open
```

Open the generated URL on Windows PowerShell:

```powershell
docker run --pull=always --rm ghcr.io/bobiene/containerruntimeprobe:preview sample --url-only | ForEach-Object { Start-Process $_ }
```

Open the generated URL on macOS:

```bash
docker run --pull=always --rm ghcr.io/bobiene/containerruntimeprobe:preview sample --url-only | xargs open
```

### Docker Compose / Portainer Stack

Use this stack to collect both a machine-readable report and a quick-submit issue URL:

```yaml
services:
  container-runtime-probe-json:
    image: ghcr.io/bobiene/containerruntimeprobe:preview
    container_name: container-runtime-probe-json
    command: ["--format", "json"]
    pull_policy: always
    restart: "no"

  container-runtime-probe-submit:
    image: ghcr.io/bobiene/containerruntimeprobe:preview
    container_name: container-runtime-probe-submit
    command: ["sample", "--url-only"]
    pull_policy: always
    restart: "no"
```

For Portainer, deploy this as a stack.
- Open **container-runtime-probe-submit** logs → copy the generated GitHub issue URL and submit the report.
- Open **container-runtime-probe-json** logs → view the full JSON report for debugging or CI usage.

### Kubernetes

Use this Job to print the runtime report:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: container-runtime-probe
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: container-runtime-probe
          image: ghcr.io/bobiene/containerruntimeprobe:preview
          imagePullPolicy: Always
```

URL-only variant:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: container-runtime-probe-url
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: container-runtime-probe
          image: ghcr.io/bobiene/containerruntimeprobe:preview
          imagePullPolicy: Always
          args: ["sample", "--url-only"]
```

Apply and inspect logs:

```bash
kubectl apply -f probe-job.yaml
kubectl logs job/container-runtime-probe
```

### Other runtimes

If you use another OCI-compatible runtime, run the same image there and submit the generated URL or full JSON report.

Examples:

```bash
podman run --pull=always --rm ghcr.io/bobiene/containerruntimeprobe:preview
nerdctl run --pull=always --rm ghcr.io/bobiene/containerruntimeprobe:preview sample --url-only
```

Reports are especially valuable from Podman, containerd-based systems, Docker-in-Docker setups, LXC/LXD environments, CI runners, and vendor-managed appliance platforms.

## Supported / interesting environments

Reports are useful from many environments, especially:

- Docker
  - Native Linux Docker
  - Docker Desktop on Windows / WSL2
  - Docker Desktop on macOS
  - Docker on NAS or appliance systems
- Docker Compose / Portainer Stack
  - Compose on Linux servers
  - Compose on NAS systems
  - Portainer-managed stacks
  - Homelab environments
- Kubernetes
  - Managed Kubernetes
  - Local Kubernetes
  - k3s / microk8s / kind / minikube
  - Edge Kubernetes
- Other runtimes / environments
  - Podman
  - containerd
  - Docker-in-Docker
  - LXC/LXD
  - Synology / QNAP / Unraid
  - Proxmox-hosted containers or VMs
  - Cloud VMs running containers
  - CI runners

## Especially useful sample targets

We are especially interested in reports from:

- Docker Desktop on Windows with WSL2
- Docker Desktop on macOS
- Native Linux Docker hosts
- Docker Compose setups
- Portainer stacks
- Synology NAS
- QNAP NAS
- Unraid
- Proxmox VMs / containers
- k3s / microk8s / minikube / kind
- Managed Kubernetes clusters
- GitHub Actions / CI runners
- Cloud VMs with Docker installed

## How classification works

Classification uses the evidence visible from inside the container. The goal is to classify the environment conservatively, not to guess an exact host OS in every case.

Examples:

- `microsoft-standard-WSL2` in `/proc/version` usually means Docker is running on Windows via WSL2.
- A modern distribution kernel usually indicates a standard Linux host.
- A very old/custom kernel combined with a modern container image can indicate a NAS or appliance host.

These are heuristics rather than guarantees because vendors can customize kernels, container platforms can mask details, and visibility varies by environment.

Signals are combined across kernel markers, runtime APIs, orchestrator hints, and safe metadata. Results are best-effort and improve as more real-world samples are submitted.

## Submit a report via GitHub Issue

The fastest path is to run the container with `sample --url-only`, open the generated URL, review the prefilled issue body, and submit it.

If possible, also keep the full JSON output for debugging or attach a reviewed redacted report to the issue. Real samples are useful even when classification is incomplete or partially wrong.

## Development

Build and test from the repository root:

```bash
dotnet build ContainerRuntimeProbe.sln -c Release
dotnet test ContainerRuntimeProbe.sln -c Release --no-build
```

Useful commands:

```bash
dotnet pack ContainerRuntimeProbe.sln -c Release --no-build -o artifacts/packages
docker build -f docker/Dockerfile.test -t container-runtime-probe:test .
docker run --rm container-runtime-probe:test
```
