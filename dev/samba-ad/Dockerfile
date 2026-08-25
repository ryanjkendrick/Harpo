# Samba Active Directory domain controller for testing Harpo's LDAP login path
# without a real DC. Lab use only — never expose this to a network you care about.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        samba samba-ad-provision samba-dsdb-modules samba-vfs-modules winbind ldb-tools acl attr \
    && rm -rf /var/lib/apt/lists/* \
    # The distro's default smb.conf must not exist when we provision the domain.
    && rm -f /etc/samba/smb.conf

COPY --chmod=755 entrypoint.sh /entrypoint.sh

# 389 LDAP, 636 LDAPS (Harpo uses 636)
EXPOSE 389 636

# Anonymous rootDSE query — answers once the directory is actually serving LDAP.
HEALTHCHECK --interval=10s --timeout=5s --start-period=90s --retries=12 \
    CMD ldbsearch -H ldap://127.0.0.1 -s base -b '' defaultNamingContext >/dev/null 2>&1 || exit 1

VOLUME ["/var/lib/samba", "/etc/samba"]
ENTRYPOINT ["/entrypoint.sh"]
