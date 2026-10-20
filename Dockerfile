# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy solution and project files
COPY *.slnx ./
COPY Directory.Build.props ./
COPY Directory.Packages.props ./
COPY global.json ./
COPY src/OpenIdProbe.Core/*.csproj src/OpenIdProbe.Core/
COPY src/OpenIdProbe.Protocol/*.csproj src/OpenIdProbe.Protocol/
COPY src/OpenIdProbe.Reporting/*.csproj src/OpenIdProbe.Reporting/
COPY src/OpenIdProbe.Cli/*.csproj src/OpenIdProbe.Cli/

# Restore dependencies
RUN dotnet restore src/OpenIdProbe.Cli/OpenIdProbe.Cli.csproj

# Copy source code
COPY src/ src/

# Build release
RUN dotnet publish src/OpenIdProbe.Cli/OpenIdProbe.Cli.csproj \
    -c Release \
    -o /app/publish \
    --no-restore

# Runtime stage
FROM mcr.microsoft.com/dotnet/runtime:10.0 AS runtime
WORKDIR /app

# Create non-root user for security
RUN groupadd --gid 1000 probe && \
    useradd --uid 1000 --gid 1000 --shell /bin/bash probe

COPY --from=build /app/publish .

# Switch to non-root user
USER probe

ENTRYPOINT ["dotnet", "openid-probe.dll"]
