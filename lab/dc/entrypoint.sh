#!/bin/bash
# Provision the Samba AD domain on first boot, seed test objects, then run the
# DC in the foreground. Idempotent: re-runs skip provisioning if the DB exists.
set -euo pipefail

PRIVATE_DIR=/var/lib/samba/private
MARKER="${PRIVATE_DIR}/.rpcng-provisioned"

if [ ! -f "${MARKER}" ]; then
    echo "[lab] provisioning AD domain ${DOMAIN} (${REALM}) ..."

    # samba-tool refuses to provision over an existing smb.conf.
    rm -f /etc/samba/smb.conf

    samba-tool domain provision \
        --use-rfc2307 \
        --realm="${REALM}" \
        --domain="${DOMAIN}" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --adminpass="${ADMIN_PASSWORD}"

    # Make the generated krb5.conf the system default (useful for in-container
    # kinit / smbclient smoke tests).
    cp -f "${PRIVATE_DIR}/krb5.conf" /etc/krb5.conf

    echo "[lab] seeding users, groups and shares ..."
    /usr/local/bin/seed.sh

    touch "${MARKER}"
    echo "[lab] provisioning complete."
else
    echo "[lab] existing domain found, skipping provisioning."
fi

echo "[lab] starting Samba AD DC (${REALM}) ..."
exec samba --interactive --debuglevel=1
