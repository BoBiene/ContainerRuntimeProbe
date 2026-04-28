# Compact format `crp1`

The compact sample line is a semicolon-delimited ASCII payload optimized for GitHub issue URLs.

Canonical section order:

```text
crp1;cls=...;conf=...;host=...;hw=...;fp=...;p=...;sig=...;sec=...
```

Guidelines:

- use normalized short tokens instead of raw evidence
- keep the sample ASCII-only and URL-safe
- never include hostnames, container IDs, IPs, MAC addresses, tokens, or raw metadata documents
- prefer dense hints such as `cg:docker`, `mt:overlay`, `kf:WSL2`, and `api:docker`
- preserve `kernel.flavor` even when `PlatformVendor` is still `Unknown`
