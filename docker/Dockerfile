FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY . .
RUN case "$TARGETARCH" in \
        amd64) runtime_id="${TARGETOS}-x64" ;; \
        arm64) runtime_id="${TARGETOS}-arm64" ;; \
        *) echo "Unsupported target architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && dotnet publish src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj \
        -c Release -r "$runtime_id" -p:PublishTrimmed=true --self-contained true -o /app

FROM mcr.microsoft.com/dotnet/runtime-deps:8.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["/app/ContainerRuntimeProbe.Tool"]
