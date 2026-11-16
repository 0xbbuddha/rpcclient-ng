# rpcclient-ng test lab

A throwaway Active Directory domain controller in a container, pre-seeded with
accounts, groups, rights and a share that exercise **every** `rpcclient-ng`
command — including the risky-flag enrichment (AS-REP roastable, pwd-not-
required, delegation, descriptions) and the SAMR write operations.

The DC is **Samba in AD DC mode**, which speaks the same MS-RPC stacks the tool
attacks: SAMR, LSAT, LSA policy, srvsvc and wkssvc over named pipes.

> ⚠️ Lab only. Isolated bridge network, throwaway domain. Never expose it.

## Topology

| | |
|---|---|
| Realm (DNS) | `LAB.LOCAL` |
| Domain (NetBIOS) | `LAB` |
| DC hostname | `DC01` (`dc01.lab.local`) |
| Fixed IP | `172.28.0.10` (also published on `127.0.0.1`) |
| Domain admin | `Administrator` / `Passw0rd!2024` |

### Seeded objects

| Object | Purpose / flags exercised |
|--------|---------------------------|
| `Administrator` | privileged account for admin-only commands + write ops |
| `j.doe` | plain standard user — confirms `ACCESS_DENIED` paths |
| `svc_backup` | `PWD_NEVER_EXPIRES` + `AS-REP_ROASTABLE` (DONT_REQ_PREAUTH) + juicy description |
| `svc_sql` | `PASSWD_NOTREQD` + credentials in the description |
| `websvc` | `TRUSTED_FOR_DELEG` (unconstrained delegation) |
| `h.admin` | member of **Domain Admins** (privileged-group recon) |
| `x.leaver` | disabled — exercises the `DISABLED` tag |
| `IT_Admins`, `Share_Readers` | custom groups with members |
| `Backups` share | non-default share for `netshareenum` |

## Start

```sh
cd lab
docker compose up --build -d
# first boot provisions + seeds the domain; watch it finish:
docker compose logs -f dc01      # wait for "starting Samba AD DC"
```

(Optional) resolve the FQDN on the host — only needed for Kerberos:

```sh
echo '172.28.0.10  dc01.lab.local dc01 lab.local LAB' | sudo tee -a /etc/hosts
```

## Run rpcclient-ng against it

The `rpcng` wrapper builds the binary and fills in lab credentials/target. It
dials `127.0.0.1` by default, so NTLM works without touching `/etc/hosts`.

```sh
./lab/rpcng                      # interactive shell as Administrator
./lab/rpcng -c sweep             # one-shot
./lab/rpcng --user j.doe -c sweep
./lab/rpcng --null -c lsaquery   # anonymous / null session
```

Or call the binary directly:

```sh
./rpcclient-ng -d lab.local -u Administrator -p 'Passw0rd!2024' -dc-ip 127.0.0.1 dc01.lab.local
```

### Run the whole command matrix

```sh
./lab/test-all.sh               # all read-only commands
RUN_WRITE=1 ./lab/test-all.sh   # also create/modify/delete a throwaway user
```

## Command → test matrix

Everything below is covered by `test-all.sh`. Unprivileged behaviour (the
`ACCESS_DENIED` paths) is verified by re-running with `--user j.doe`.

| Command | How to test |
|---------|-------------|
| `sweep` | `./lab/rpcng -c sweep` — expect svc_backup/svc_sql/websvc highlighted |
| `enumdomains` / `use` | `-c enumdomains` → `LAB`, `Builtin` |
| `enumdomusers` | all seeded users; try `--user j.doe` to hit the LSAT RID-cycle fallback |
| `enumdomgroups` / `enumdomaliases` | lists `IT_Admins`, `Share_Readers`, builtin aliases |
| `querydispinfo` | descriptions shown; flags blank on Samba (see caveats — use `queryuser`) |
| `queryuser <rid\|name>` | `-c 'queryuser svc_backup'` |
| `queryusergroups <rid>` | `-c 'queryusergroups 500'` |
| `querygroupmem <rid>` | `-c 'querygroupmem 512'` → Administrator + h.admin |
| `queryaliasmem <rid>` | `-c 'queryaliasmem 1101'`; for Builtin 544 `use BUILTIN` first |
| `getdompwinfo` | domain password policy |
| `lookupnames` / `lookupsids` | `-c 'lookupnames svc_backup'` |
| `ridcycle` | `-c 'ridcycle 500 520'` |
| `lsaquery` / `getusername` | policy + whoami |
| `lsaenumtrustdom` | empty on a single-domain lab (add a trust to populate) |
| `lsaenumprivs` / `lsaenumaccounts` / `lsaenumacctrights` | LSA rights; see note below to grant a custom right |
| `netservergetinfo` / `wkstagetinfo` | identity → `DC01` |
| `netshareenum` | includes the `Backups` share |
| `netsessenum` | works via level-1 fallback; `ACCESS_DENIED` as `j.doe` |
| `netwkstauserenum` | admin-only; unsupported by Samba (see caveats) |
| `createdomuser` / `deldomuser` | `RUN_WRITE=1 ./lab/test-all.sh` |
| `addgroupmem` / `delgroupmem` | add/remove the throwaway user to RID 512 |
| `addaliasmem` / `delaliasmem` | add/remove a SID on a LAB alias (1101); for Builtin 544 see caveats |

### Samba-specific caveats (vs a real Windows DC)

The DC is Samba, whose MS-RPC surface differs from Windows in a few spots. These
are **server** behaviours, not tool bugs (verified against Samba's own
`rpcclient`):

- **`querydispinfo` shows `Flags: -` for everyone.** Samba does not populate
  `acct_flags` in `SamrQueryDisplayInformation`. Use **`queryuser <name>`**,
  which reads `SamrQueryInformationUser` and correctly decodes
  `AS-REP_ROASTABLE`, `PWD_NEVER_EXPIRES`, `TRUSTED_FOR_DELEG`, `DISABLED`, ...
  (`sweep` highlights the risky accounts from descriptions regardless.)
- **`netwkstauserenum` fails with `nca_op_rng_error`.** Samba's `wkssvc` does
  not implement `NetrWkstaUserEnum` at all. Expect this to work only on Windows.
- **`netsessenum`** — Samba rejects levels 502/10 with `ERROR_INVALID_LEVEL`;
  the tool now falls back to level 1, which Samba supports.
- **`addaliasmem 544` (Builtin Administrators)** needs the BUILTIN domain
  selected first, which only the interactive shell can do (one-shot `-c` resets
  to LAB each run):

  ```
  rpcclient-ng (LAB)> use BUILTIN
  rpcclient-ng (BUILTIN)> addaliasmem 544 S-1-5-21-...-1103
  ```

  For a one-shot test, target a LAB-domain alias instead, e.g. `1101` (DnsAdmins).

### Grant a custom LSA right (optional)

`lsaenumaccounts` returns the domain's default privilege holders out of the box.
To make a specific seeded account show up in `lsaenumacctrights`, grant it a
right over RPC once the DC is up:

```sh
docker compose exec dc01 \
  net rpc rights grant 'LAB\svc_backup' SeBackupPrivilege \
    -U 'LAB\Administrator%Passw0rd!2024' -S 127.0.0.1
```

## Kerberos testing

```sh
# host needs the /etc/hosts entry above + a matching krb5.conf realm
docker compose exec dc01 cat /etc/krb5.conf   # reference config
export KRB5CCNAME=/tmp/svc.ccache
kinit svc_backup@LAB.LOCAL                     # or impacket getTGT
./rpcclient-ng -k -c enumdomgroups dc01.lab.local
```

Kerberos requires the target as the DC FQDN (so the `cifs/dc01.lab.local`
service ticket matches), a resolvable KDC, and clock within skew.

## Reset / teardown

```sh
docker compose down          # stop, keep the provisioned domain
docker compose down -v        # stop and wipe (re-provisions on next up)
```

## Extending the lab

When you add a new command to `rpcclient-ng`, seed whatever object it needs in
`dc/seed.sh` (users via `samba-tool user create`, groups via
`samba-tool group add`, shares appended to `smb.conf`), then add a `run` line to
`test-all.sh`. Re-provision with `docker compose down -v && docker compose up --build -d`.
