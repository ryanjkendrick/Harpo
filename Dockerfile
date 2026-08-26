# ---- build ----
# Pinned to the build host's own architecture: the publish output is portable
# (framework-dependent, no RID), so multi-arch builds compile once natively
# instead of once per target under QEMU emulation.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/Harpo/Harpo.csproj src/Harpo/
RUN dotnet restore src/Harpo/Harpo.csproj
COPY src/ src/
RUN dotnet publish src/Harpo/Harpo.csproj -c Release -o /app /p:UseAppHost=false

# ---- runtime ----
FROM mcr.microsoft.com/dotnet/aspnet:10.0
LABEL org.opencontainers.image.source="https://github.com/ryanjkendrick/Harpo" \
      org.opencontainers.image.description="Harpo — self-hosted team password manager: AD login, group-gated vaults, cross-site replication, offline PWA" \
      org.opencontainers.image.licenses="MIT"
# libldap is the native library System.DirectoryServices.Protocols uses to talk
# to Active Directory from Linux. (Package name differs across Debian releases.)
RUN apt-get update \
    && (apt-get install -y --no-install-recommends libldap2 || apt-get install -y --no-install-recommends libldap-2.5-0) \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app .

# /data holds the SQLite database and data-protection keys; mount a volume there.
RUN mkdir -p /data && chown app:app /data
USER app
VOLUME /data

ENV ASPNETCORE_URLS=http://+:8080 \
    ConnectionStrings__Harpo="Data Source=/data/harpo.db" \
    Harpo__DataProtectionKeysPath=/data/keys \
    Harpo__Icons__ImportPath=/data/icons

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080 && printf "GET /healthz HTTP/1.0\r\n\r\n" >&3 && grep -q "200 OK" <&3'

ENTRYPOINT ["dotnet", "Harpo.dll"]
