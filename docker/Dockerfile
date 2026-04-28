FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish src/ContainerRuntimeProbe.Tool/ContainerRuntimeProbe.Tool.csproj \
    -c Release -r linux-x64 -p:PublishTrimmed=true --self-contained true -o /app

FROM mcr.microsoft.com/dotnet/runtime-deps:8.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["/app/ContainerRuntimeProbe.Tool"]
