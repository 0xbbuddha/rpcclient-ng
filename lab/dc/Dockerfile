# Samba Active Directory Domain Controller for the rpcclient-ng test lab.
# Self-provisions on first boot and seeds accounts/groups/shares that exercise
# every rpcclient-ng command, including the risky-flag enrichment and the write
# operations.
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

# samba           : the AD DC itself (SAMR/LSA/srvsvc/wkssvc over MS-RPC)
# samba-dsdb/vfs  : AD directory + share modules
# winbind         : name/SID resolution
# krb5-* / ldb    : Kerberos and the ldbmodify tool used to set UAC flags
# smbclient       : handy for in-container smoke tests
RUN apt-get update && apt-get install -y --no-install-recommends \
        samba \
        samba-ad-provision \
        samba-dsdb-modules \
        samba-vfs-modules \
        winbind \
        krb5-user \
        krb5-config \
        ldb-tools \
        smbclient \
        procps \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Realm / domain / admin password come from the environment (compose sets them).
ENV REALM=LAB.LOCAL \
    DOMAIN=LAB \
    ADMIN_PASSWORD=Passw0rd!2024

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY seed.sh       /usr/local/bin/seed.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/seed.sh

# epmapper, netbios, ldap, kerberos, smb, kpasswd, global catalog
EXPOSE 53/tcp 53/udp 88/tcp 88/udp 135/tcp 139/tcp 389/tcp 389/udp \
       445/tcp 464/tcp 464/udp 636/tcp 3268/tcp 3269/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
