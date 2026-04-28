# Container Runtime Report (Docker socket mounted)

This sample is captured from the same image executed with:

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro container-runtime-probe:test
```

Expected key differences vs non-socket run:
- `runtime-api` evidence contains `socket.present: /var/run/docker.sock`
- `/_ping`, `/version`, `/info` on docker socket return `Success` or typed failure (`AccessDenied`/`Unavailable`)
- report `SecurityWarnings` contains `DOCKER_SOCKET_MOUNTED`
