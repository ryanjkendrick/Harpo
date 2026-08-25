#!/bin/bash
# Provisions a throwaway HARPO.LAB Active Directory domain on first start, then
# runs the Samba AD DC in the foreground. Test accounts (created once):
#
#   ada    — member of "Harpo Admins" → Harpo site admin
#   grace  — regular user
#
# Passwords come from USER_PASSWORD (default Passw0rd!); the built-in
# Administrator password from ADMIN_PASSWORD.
set -euo pipefail

REALM="${REALM:-HARPO.LAB}"
DOMAIN="${DOMAIN:-HARPO}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Adm1nPassw0rd!}"
USER_PASSWORD="${USER_PASSWORD:-Passw0rd!}"

# Written only after provisioning fully succeeds, so a failed/interrupted
# attempt is wiped and redone instead of leaving a half-built domain behind.
MARKER=/var/lib/samba/.harpo-provisioned

# Containers may not write security.* filesystem xattrs (that needs
# CAP_SYS_ADMIN), so store NT ACLs in a tdb file instead.
EADB_OPTION="posix:eadb = /var/lib/samba/private/eadb.tdb"

if [ ! -f "$MARKER" ]; then
    echo ">>> Provisioning Samba AD domain ${REALM} (first start)..."
    rm -f /etc/samba/smb.conf
    find /var/lib/samba -mindepth 1 -delete

    samba-tool domain provision \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --realm="${REALM}" \
        --domain="${DOMAIN}" \
        --adminpass="${ADMIN_PASSWORD}" \
        --use-rfc2307 \
        --option="${EADB_OPTION}"

    # The provision-time option must also apply at runtime.
    grep -q "posix:eadb" /etc/samba/smb.conf || \
        sed -i "/\[global\]/a\\\t${EADB_OPTION}" /etc/samba/smb.conf

    cp /var/lib/samba/private/krb5.conf /etc/krb5.conf || true

    echo ">>> Creating test users and the Harpo Admins group..."
    samba-tool user create ada "${USER_PASSWORD}" \
        --given-name=Ada --surname=Lovelace \
        --mail-address="ada@${REALM,,}"
    samba-tool user create grace "${USER_PASSWORD}" \
        --given-name=Grace --surname=Hopper \
        --mail-address="grace@${REALM,,}"
    samba-tool user setexpiry ada --noexpiry
    samba-tool user setexpiry grace --noexpiry

    samba-tool group add "Harpo Admins" --description="Harpo site administrators"
    samba-tool group addmembers "Harpo Admins" ada

    touch "$MARKER"
    echo ">>> Provisioning done."
else
    echo ">>> Domain already provisioned, starting Samba."
fi

exec samba --foreground --no-process-group --debug-stdout --debuglevel="${SAMBA_DEBUG_LEVEL:-1}"
