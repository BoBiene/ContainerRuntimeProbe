# Runtime sample fixtures

ContainerRuntimeProbe can emit a dense compact `crp1;...` sample for GitHub issue prefill and a richer redacted JSON sample for fixtures and regression tests.

Suggested maintainer workflow:

1. A user opens a prefilled GitHub issue with `container-runtime-probe sample` or `docker run --pull=always --rm ghcr.io/bobiene/container-runtime-probe:latest sample`.
2. The user optionally attaches `my-report.json` created with `docker run --pull=always --rm ghcr.io/bobiene/container-runtime-probe:latest json > my-report.json`.
3. A maintainer reviews the compact sample and the optional full redacted report.
4. Useful sanitized samples can be added under `docs/samples/examples/`.
5. `.sample.txt` files provide quick parser fixtures for compact sample tests.
6. `.sample.json` files are future regression-test inputs for classification and parsing.

Files in this directory:

- `schema.runtime-sample.v1.json` - JSON schema for sample fixtures.
- `compact-format.crp1.md` - compact sample format notes.
- `examples/` - sanitized sample fixtures used by tests.
