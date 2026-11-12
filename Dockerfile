# ---- build ----
# Pinned to the build host's own architecture: the publish output is portable
# (framework-dependent, no RID), so multi-arch builds compile once natively
# instead of once per target under QEMU emulation.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:11.0 AS build
WORKDIR /src
COPY src/Harpo/Harpo.csproj src/Harpo/
RUN dotnet restore src/Harpo/Harpo.csproj
COPY src/ src/
RUN dotnet publish src/Harpo/Harpo.csproj -c Release -o /app /p:UseAppHost=false
# The portable output carries native SQLite3MC builds for every platform it
# supports (Android, iOS, Windows, macOS, musl, RISC-V...). The image only ever
# runs on glibc Linux x64 or Arm64, so keep those two and the managed `linux`
# folder (System.DirectoryServices.Protocols) and drop the rest (~65 MB).
RUN cd /app/runtimes \
    && find . -mindepth 1 -maxdepth 1 ! -name linux ! -name linux-x64 ! -name linux-arm64 -exec rm -rf {} + \
    && ls linux/lib/*/System.DirectoryServices.Protocols.dll linux-x64/native/libsqlite3mc.so linux-arm64/native/libsqlite3mc.so

# ---- runtime ----
# Ubuntu 26.04 rather than the default 24.04: the older base carries OS-package
# CVEs (pcre2, gnutls, glibc, ...) that Ubuntu has not fixed there, and on 26.04
# libldap uses OpenSSL instead of gnutls. Check it with `docker scout quickview`.
FROM mcr.microsoft.com/dotnet/aspnet:11.0-resolute
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
