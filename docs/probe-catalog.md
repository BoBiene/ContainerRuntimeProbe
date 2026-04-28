# Probe Catalog

- `marker-files`: checks `/.dockerenv` and `/run/.containerenv`.
- `environment`: allowlisted runtime/orchestrator env markers.
- `cgroup`: reads `/proc/self/cgroup` with bounded lines.

Future phases add Docker/Podman API, Kubernetes API, and cloud metadata probes.
