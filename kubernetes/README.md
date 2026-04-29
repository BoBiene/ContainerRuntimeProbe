# Kubernetes quick run

This folder contains ready-to-apply manifests for running Container Runtime Probe in a cluster.

Files:

- `job.yaml`: prints the full probe report to job logs
- `job-url.yaml`: prints only the prefilled GitHub issue URL
- `run-test.ps1`: applies a job with `kubectl`, waits for completion, and prints logs

Examples:

```powershell
.\kubernetes\run-test.ps1
.\kubernetes\run-test.ps1 -Mode UrlOnly
.\kubernetes\run-test.ps1 -Namespace default -Cleanup
```

Raw kubectl usage:

```bash
kubectl apply -f kubernetes/job.yaml
kubectl logs job/container-runtime-probe

kubectl apply -f kubernetes/job-url.yaml
kubectl logs job/container-runtime-probe-url
```

If you want to test a different image tag, use the helper script:

```powershell
.\kubernetes\run-test.ps1 -Image ghcr.io/bobiene/containerruntimeprobe:preview
```
