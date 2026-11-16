#!/bin/bash
# Seed the freshly provisioned domain with objects that exercise every
# rpcclient-ng command. Runs offline against the local sam.ldb, so Samba does
# not need to be running yet.
set -euo pipefail

SAM_LDB=/var/lib/samba/private/sam.ldb

# Base DN derived from the realm: LAB.LOCAL -> DC=lab,DC=local
BASE_DN="DC=$(echo "${REALM}" | tr 'A-Z.' 'a-z,' | sed 's/,/,DC=/g')"

# userAccountControl bit values (decimal) --------------------------------------
UAC_NORMAL=512         # 0x000200 NORMAL_ACCOUNT
UAC_NOTREQD=32         # 0x000020 PASSWD_NOTREQD
UAC_PWD_NEVER=65536    # 0x010000 DONT_EXPIRE_PASSWORD
UAC_DELEG=524288       # 0x080000 TRUSTED_FOR_DELEGATION
UAC_NOPREAUTH=4194304  # 0x400000 DONT_REQUIRE_PREAUTH (AS-REP roastable)

newuser() {
    # newuser <name> <password> <description> [--option ...]
    local name="$1" pass="$2" desc="$3"; shift 3
    samba-tool user create "${name}" "${pass}" --description="${desc}" "$@"
}

set_uac() {
    # set_uac <sam-account-name> <decimal-uac>
    local name="$1" uac="$2"
    ldbmodify -H "${SAM_LDB}" <<EOF
dn: CN=${name},CN=Users,${BASE_DN}
changetype: modify
replace: userAccountControl
userAccountControl: ${uac}
EOF
}

# --- Users --------------------------------------------------------------------

# Plain standard account: used to confirm ACCESS_DENIED paths (netsessenum,
# write ops, ...) behave from an unprivileged context.
newuser j.doe 'User123!Pass' 'Standard domain user'

# Backup service: password never expires + AS-REP roastable + a juicy desc.
newuser svc_backup 'Backup123!Pass' 'Nightly backup service - do not disable'
set_uac svc_backup $((UAC_NORMAL | UAC_PWD_NEVER | UAC_NOPREAUTH))

# SQL service: PASSWD_NOTREQD (weak/empty password allowed) + creds in desc.
newuser svc_sql 'Sql123!Password' 'SQL service, temp pass Summer2024!'
set_uac svc_sql $((UAC_NORMAL | UAC_NOTREQD))

# Web app pool: unconstrained delegation.
newuser websvc 'Web123!Password' 'IIS app pool (delegation enabled)'
set_uac websvc $((UAC_NORMAL | UAC_DELEG))

# Helpdesk admin: member of Domain Admins (shows up in privileged-group recon).
newuser h.admin 'Helpdesk123!Pass' 'Helpdesk administrator'

# Disabled leaver: exercises the DISABLED tag.
newuser x.leaver 'Leaver123!Pass' 'Former employee - disabled'
samba-tool user disable x.leaver

# --- Groups -------------------------------------------------------------------

samba-tool group add IT_Admins --description="Second-tier IT administrators"
samba-tool group add Share_Readers --description="Allowed to read shares"

samba-tool group addmembers "Domain Admins" h.admin
samba-tool group addmembers IT_Admins h.admin,svc_backup
samba-tool group addmembers Share_Readers j.doe,svc_sql

# LSA privilege holders (lsaenumaccounts / lsaenumacctrights) are the domain's
# default privileged principals (Administrators, Domain Admins, ...); to grant
# a specific test account a right, run post-start (DC must be up), e.g.:
#   net rpc rights grant 'LAB\svc_backup' SeBackupPrivilege \
#       -U 'LAB\Administrator%'"${ADMIN_PASSWORD}" -S 127.0.0.1

# --- Non-default share (exercises netshareenum) -------------------------------
mkdir -p /srv/backups
chmod 0777 /srv/backups
cat >> /etc/samba/smb.conf <<'EOF'

[Backups]
    path = /srv/backups
    comment = Nightly backup drop (restricted)
    read only = no
    browseable = yes
EOF

echo "[lab] seed complete:"
echo "      domain admin : Administrator / ${ADMIN_PASSWORD}"
echo "      std user     : j.doe / User123!Pass"
echo "      AS-REP roast : svc_backup (DONT_REQ_PREAUTH + PWD_NEVER_EXPIRES)"
echo "      passwd-notreqd: svc_sql"
echo "      delegation   : websvc"
echo "      domain admin member: h.admin"
