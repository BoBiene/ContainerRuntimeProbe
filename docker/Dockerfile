FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY . .
RUN target_os="${TARGETOS:-linux}" \
    && target_arch="${TARGETARCH:-amd64}" \
    && case "$target_arch" in \
        amd64) runtime_id="${target_os}-x64" ;; \
        arm64) runtime_id="${target_os}-arm64" ;; \
        *) echo "Unsupported target architecture: $target_arch" >&2; exit 1 ;; \
    esac \
    && dotnet publish src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj \
        -c Release -r "$runtime_id" -p:PublishTrimmed=true --self-contained true -o /app

FROM mcr.microsoft.com/dotnet/runtime-deps:8.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["/app/ContainerRuntimeProbe.Tool"]
