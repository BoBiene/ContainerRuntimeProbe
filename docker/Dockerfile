FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG ARM64_PUBLISH_AOT=false
ARG MINVER_VERSION_OVERRIDE
ARG MINVER_BUILD_METADATA
WORKDIR /src
RUN apk add --no-cache clang llvm musl-dev zlib-dev zlib-static
COPY Directory.Build.props ./
COPY src/ContainerRuntimeProbe/ContainerRuntimeProbe.csproj src/ContainerRuntimeProbe/
COPY src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj src/ContainerRuntimeProbe.Tool/
RUN target_os="${TARGETOS:-linux}" \
    && target_arch="${TARGETARCH:-amd64}" \
    && build_platform="${BUILDPLATFORM:-unknown}" \
    && publish_aot=true \
    && case "$target_arch" in \
        amd64) runtime_id="${target_os}-musl-x64" ;; \
        arm64) runtime_id="${target_os}-musl-arm64"; publish_aot="${ARM64_PUBLISH_AOT}" ;; \
        arm) runtime_id="${target_os}-musl-arm"; publish_aot=false ;; \
        *) echo "Unsupported target architecture: $target_arch" >&2; exit 1 ;; \
    esac \
    && if [ "$target_arch" = "arm64" ] \
        && [ "$publish_aot" = "true" ] \
        && [ "$build_platform" != "${target_os}/arm64" ]; then \
        echo "Native AOT for $runtime_id requires a real ${target_os}/arm64 builder." >&2; \
        echo "Current build platform: $build_platform." >&2; \
        exit 1; \
    fi \
    && dotnet restore src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj \
        -r "$runtime_id" -p:PublishAot="$publish_aot"
COPY . .
RUN target_os="${TARGETOS:-linux}" \
    && target_arch="${TARGETARCH:-amd64}" \
    && build_platform="${BUILDPLATFORM:-unknown}" \
    && minver_version_override="${MINVER_VERSION_OVERRIDE}" \
    && minver_build_metadata="${MINVER_BUILD_METADATA}" \
    && publish_aot=true \
    && case "$target_arch" in \
        amd64) runtime_id="${target_os}-musl-x64" ;; \
        arm64) runtime_id="${target_os}-musl-arm64"; publish_aot="${ARM64_PUBLISH_AOT}" ;; \
        arm) runtime_id="${target_os}-musl-arm"; publish_aot=false ;; \
        *) echo "Unsupported target architecture: $target_arch" >&2; exit 1 ;; \
    esac \
    && if [ "$target_arch" = "arm64" ] \
        && [ "$publish_aot" = "true" ] \
        && [ "$build_platform" != "${target_os}/arm64" ]; then \
        echo "Native AOT for $runtime_id requires a real ${target_os}/arm64 builder." >&2; \
        echo "Current build platform: $build_platform." >&2; \
        exit 1; \
    elif [ "$target_arch" = "arm64" ] && [ "$publish_aot" != "true" ]; then \
        echo "Native AOT is disabled for $runtime_id by default because"; \
        echo "linux-musl-arm64 AOT builds are unsupported under buildx/qemu."; \
        echo "Set ARM64_PUBLISH_AOT=true on real arm64 builders to enable it."; \
    elif [ "$target_arch" = "arm" ]; then \
        echo "Native AOT is disabled for $runtime_id because .NET Native AOT"; \
        echo "on Linux supports x64 and arm64, but not 32-bit arm."; \
    fi \
    && minver_args="" \
    && if [ -n "$minver_version_override" ]; then \
        minver_args="$minver_args -p:MinVerVersionOverride=$minver_version_override"; \
    fi \
    && if [ -n "$minver_build_metadata" ]; then \
        minver_args="$minver_args -p:MinVerBuildMetadata=$minver_build_metadata -p:SourceRevisionId=$minver_build_metadata -p:IncludeSourceRevisionInInformationalVersion=true"; \
    fi \
    && dotnet publish src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj \
        -c Release \
        -r "$runtime_id" \
        -p:PublishTrimmed=true \
        -p:PublishAot="$publish_aot" \
        --self-contained \
        --no-restore \
        $minver_args \
        -o /app

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-alpine
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["/app/ContainerRuntimeProbe.Tool"]
