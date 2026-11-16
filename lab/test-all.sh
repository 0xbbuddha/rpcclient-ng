#!/usr/bin/env bash
# Smoke-test every rpcclient-ng command against the lab DC. Read-only commands
# run first; write operations (guarded by RUN_WRITE=1) create and then clean up
# a throwaway user. Each command is run one-shot via `-c`.
#
#   ./lab/test-all.sh              # read-only sweep of all commands
#   RUN_WRITE=1 ./lab/test-all.sh  # also exercise the SAMR write ops
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RPCNG="${HERE}/rpcng"

pass=0 fail=0

run() {
    local desc="$1"; shift
    echo
    echo "=== ${desc} :: $* ==="
    if "${RPCNG}" -c "$*"; then
        pass=$((pass + 1))
    else
        echo "!!! FAILED: $*"
        fail=$((fail + 1))
    fi
}

echo "########## Recon report ##########"
run "one-shot recon"            sweep

echo "########## Enumeration (SAMR) ##########"
run "list SAM domains"          enumdomains
run "enumerate users"           enumdomusers
run "enumerate groups"          enumdomgroups
run "enumerate aliases"         enumdomaliases
run "users + flags"             querydispinfo
run "query a user by name"      "queryuser Administrator"
run "query a user by name"      "queryuser svc_backup"
run "user's groups (RID 500)"   "queryusergroups 500"
run "group members (512=DA)"    "querygroupmem 512"
run "alias members (1101)"      "queryaliasmem 1101"
run "password policy"           getdompwinfo

echo "########## Translation (LSAT) ##########"
run "names -> SIDs"             "lookupnames Administrator svc_backup"
run "SIDs -> names"             "lookupsids S-1-5-32-544 S-1-5-32-551"
run "RID cycling"               "ridcycle 500 520"

echo "########## Policy / trusts / rights (LSA) ##########"
run "LSA policy"                lsaquery
run "current username"          getusername
run "trusted domains"           lsaenumtrustdom
run "known privileges"          lsaenumprivs
run "privilege holders"         lsaenumaccounts
run "rights of Administrators"  "lsaenumacctrights S-1-5-32-544"

echo "########## Host / shares / sessions (srvsvc / wkssvc) ##########"
run "server info"               netservergetinfo
run "workstation info"          wkstagetinfo
run "share enumeration"         netshareenum
run "open sessions (admin)"     netsessenum
run "logged-on users (admin)"   netwkstauserenum

if [ "${RUN_WRITE:-0}" = "1" ]; then
    echo "########## Write operations (SAMR) ##########"
    victim="labtest_$$"
    run "create user"           "createdomuser ${victim}"
    run "enable user (by name)"  "enabledomuser ${victim}"
    run "disable user (by name)" "disabledomuser ${victim}"
    # Resolve the new account's full SID, then derive its RID (last component).
    sid="$("${RPCNG}" -c "lookupnames ${victim}" 2>/dev/null | grep -oE 'S-1-5-21-[0-9-]+' | head -1)"
    rid="${sid##*-}"
    if [ -n "${sid:-}" ] && [ -n "${rid:-}" ]; then
        run "add to Domain Admins (group)"  "addgroupmem 512 ${rid}"
        run "remove from Domain Admins"     "delgroupmem 512 ${rid}"
        # addaliasmem/delaliasmem open the alias in the *current* domain; RID
        # 1101 (DnsAdmins) lives in LAB. The classic Builtin Administrators
        # (544) abuse needs `use BUILTIN` first, so it is only reachable from
        # the interactive shell, not a one-shot.
        run "add to a local alias (DnsAdmins)"      "addaliasmem 1101 ${sid}"
        run "list alias members (shows new member)" "queryaliasmem 1101"
        run "remove from the local alias"           "delaliasmem 1101 ${sid}"
        # setuserpass is EXPECTED to fail against Samba (sealed-connection key
        # limitation; works against Windows DCs). Run it for visibility without
        # counting it in the pass/fail totals.
        echo
        echo "=== setuserpass (expected to FAIL against Samba) :: setuserpass ${victim} S0me!Pass2026 ==="
        "${RPCNG}" -c "setuserpass ${victim} 'S0me!Pass2026'" || true
        run "delete user"                           "deldomuser ${rid}"
    else
        echo "!!! could not resolve SID for ${victim}; skipping dependent write tests"
        fail=$((fail + 1))
    fi
fi

echo
echo "########## summary: ${pass} passed, ${fail} failed ##########"
[ "${fail}" -eq 0 ]
