FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
RUN apk add --no-cache clang llvm musl-dev zlib-dev zlib-static
COPY . .
RUN target_os="${TARGETOS:-linux}" \
    && target_arch="${TARGETARCH:-amd64}" \
    && case "$target_arch" in \
        amd64) runtime_id="${target_os}-musl-x64" ;; \
        arm64) runtime_id="${target_os}-musl-arm64" ;; \
        *) echo "Unsupported target architecture: $target_arch" >&2; exit 1 ;; \
    esac \
    && dotnet publish src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj \
        -c Release -r "$runtime_id" -p:PublishTrimmed=true -p:PublishAot=true --self-contained -o /app

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-alpine
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["/app/ContainerRuntimeProbe.Tool"]
