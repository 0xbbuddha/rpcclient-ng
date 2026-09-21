# rpcclient-ng

A modern, offensive-oriented MS-RPC client for Active Directory enumeration, a
Go rewrite of Samba's `rpcclient`, shipped as a single static binary.

Samba's `rpcclient` is a fine tool, but it was built to *test* MS-RPC, not to
attack it: a blind REPL, raw structure dumps, no JSON, no RID cycling, and a
dependency on `samba-common-bin`. `rpcclient-ng` keeps the command names you
already know and reworks the tool for red-team use: it interprets results,
enriches them, and works around common access restrictions instead of stopping
at the first `NT_STATUS_ACCESS_DENIED`.

> **Not affiliated with the Samba project.** The command syntax intentionally
> mirrors `rpcclient` for muscle-memory compatibility; the implementation shares
> no code with it.

## Highlights

- **Single static binary**: no Python, no Samba, cross-compiles to Linux, Windows and macOS.
- **Automatic fallbacks**: `enumdomusers` transparently switches to LSAT RID cycling when SAMR enumeration is denied.
- **Enriched output**: account-control flags are decoded to readable tags (`DISABLED`, `AS-REP_ROASTABLE`, `PWD_NEVER_EXPIRES`, `TRUSTED_FOR_DELEG`, ...) instead of raw hex.
- **Multiple RPC interfaces**: SAMR, LSAT, LSA policy and Server Service in one shell.
- **Interactive shell** with tab-completion, plus a one-shot mode for scripting.
- **Table or JSON output** for piping into other tooling.
- **Modern authentication**: password and pass-the-hash (Kerberos planned).

## Installation

```sh
go install github.com/0xbbuddha/rpcclient-ng@latest
```

Or build from source (Go 1.27+):

```sh
git clone https://github.com/0xbbuddha/rpcclient-ng
cd rpcclient-ng
go build -o rpcclient-ng .
```

## Usage

```
rpcclient-ng [flags] <target>
```

| Flag | Description |
|------|-------------|
| `-u` | Username |
| `-p` | Password |
| `-H` | NT hash for pass-the-hash (`LM:NT` or bare `NT`) |
| `-d` | Domain (NetBIOS or FQDN) |
| `-c` | Run a single command, then exit |
| `-json` | Emit output as JSON |
| `-no-seal` | Disable DCERPC packet privacy (sealing) |

`<target>` is the domain controller's hostname or IP.

Open an interactive shell:

```sh
rpcclient-ng -d corp.local -u j.doe -p 'Passw0rd!' dc01.corp.local
```

Run a single command and exit:

```sh
rpcclient-ng -d corp.local -u j.doe -p 'Passw0rd!' -c enumdomgroups dc01.corp.local
```

Pass-the-hash, JSON output:

```sh
rpcclient-ng -d corp.local -u j.doe -H aad3b435...:e19ccf75... -json -c querydispinfo dc01.corp.local
```

## Commands

### Enumeration (SAMR)

| Command | Description |
|---------|-------------|
| `enumdomains` | List the SAM domains hosted by the server and their SIDs |
| `use <domain>` | Set the active domain used by enumeration commands |
| `enumdomusers` | Enumerate users; falls back to LSAT RID cycling if SAMR is denied |
| `enumdomgroups` | Enumerate groups in the active domain |
| `enumdomaliases` | Enumerate aliases (local groups) in the active domain |
| `querydispinfo` | List users with description and decoded account-control flags |
| `queryuser <rid\|name>` | Show general information and flags for a user |
| `queryusergroups <rid>` | List the groups a user is a member of |
| `querygroupmem <rid>` | List the members of a group |
| `getdompwinfo` | Show the domain password policy |

### Translation (LSAT)

| Command | Description |
|---------|-------------|
| `lookupnames <name>...` | Translate account names to SIDs |
| `lookupsids <sid>...` | Translate SIDs to account names |
| `ridcycle [start] [end]` | Sweep RIDs against the domain SID and resolve them (default 500-1100) |

### Policy & host (LSA / srvsvc)

| Command | Description |
|---------|-------------|
| `lsaquery` | Query LSA policy for account and DNS domain information (name, SID, forest) |
| `getusername` | Show the account name and domain of the authenticated user |
| `netshareenum` | Enumerate the shared resources on the target |

Type `help` in the shell for the full list, or `help <command>` for details.

## Example session

```
rpcclient-ng (CORP)> enumdomusers
[!] SAMR user enumeration denied by server; falling back to LSAT RID cycling (500-1500)
RID   Name             SID
----  ----             ----
500   CORP\Administrator   S-1-5-21-...-500
1109  CORP\svc_backup      S-1-5-21-...-1109

rpcclient-ng (CORP)> querydispinfo
RID   Name           Description                     Flags
----  ----           ----                            ----
500   Administrator  Built-in admin account          PWD_NEVER_EXPIRES
1109  svc_backup     Backup service                  PWD_NEVER_EXPIRES,AS-REP_ROASTABLE

rpcclient-ng (CORP)> netshareenum
Share    Type            Remark
----     ----            ----
IPC$     IPC (SPECIAL)   Remote IPC
SYSVOL   DISK            Logon server share
Backups  DISK            Nightly backups
```

## Legal

`rpcclient-ng` is intended for authorized security testing, red-team engagements,
and educational use only. Only use it against systems you own or have explicit
written permission to test. You are responsible for complying with all
applicable laws; the authors accept no liability for misuse.

## Credits

Built on [`go-msrpc`](https://github.com/oiweiwei/go-msrpc) for the DCERPC,
SAMR, LSA and srvsvc protocol stacks, and
[`chzyer/readline`](https://github.com/chzyer/readline) for the interactive
shell. Inspired by Samba's `rpcclient`

## License

MIT.
