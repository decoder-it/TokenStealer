# TokenStealer v2

A Windows token enumerator and impersonator for authorized security testing.
> A simple tool I wrote some time ago for stealing and playing with Windows tokens.
> Parts of code have been taken and adatpted from https://github.com/FSecureLABS/incognito

The tool walks the system handle table, finds token handles owned by other
processes, and (when it holds the required privileges) launches a program with a
chosen token. It is a post-exploitation tool: it assumes you already have
administrative or `SYSTEM` access on the host.
> Use only on systems you own or are explicitly authorized to test.

## Requirements

- Windows (x64 recommended), Visual Studio 2022 or later. This build was produced with VS 2026
- `SeDebugPrivilege` to open other processes.
- Either `SeAssignPrimaryTokenPrivilege` or `SeImpersonatePrivilege` to launch a
  process with a stolen token. Run elevated; `SYSTEM` sees the most tokens.
- A free TCP port on `127.0.0.1` for the interactive bridge (default `4444`).

Without the privileges above the tool still runs, but it can only see and use
tokens belonging to its own process.
## Releases
A prebuilt x64 release is also available, so you do not have to build from  source:
 - https://github.com/decoder-it/TokenStealer/releases
<br>
Download the latest `TokenStealer.exe` from the Releases page and run it from   an elevated (Administrator/SYSTEM) prompt. Building from source is only needed  if you want to modify or verify the code.

## Build

The repository ships an MSVC solution/project (`TokenStealer.sln`). `TokenStealer_v2.cpp`
is the current implementation.

1. Open `TokenStealer.sln` in Visual Studio.
2. Make `TokenStealer_v2.cpp` the only compiled source (remove or exclude
   `TokenStealer.cpp`, since both define `wmain`).
3. Build **x64** (Release or Debug), Unicode character set.

A command-line build works too:

```bat
cl /EHsc /W4 /DUNICODE /D_UNICODE TokenStealer_v2.cpp ntdll.lib advapi32.lib ws2_32.lib
```

`winsock2.h` is included before `windows.h`; `ws2_32.lib` is linked via
`#pragma comment`, but it is listed above for clarity.

## Usage

```
TokenStealer.exe [filters] [-l] [--unique] [--csv|--json]
TokenStealer.exe [filters] -c <program> [-x <index>]
TokenStealer.exe [-i] [--nobridge] [-P <port>]
```

If `-c` is omitted the tool lists tokens instead of launching anything. Plain
`-l` in a real console opens the interactive menu (see below); redirection or
`--csv`/`--json` keeps the textual output.

### Filters

| Flag | Meaning |
|------|---------|
| `-p <pid>` | Only tokens owned by process `<pid>`. |
| `-u <DOMAIN\user>` | Only tokens for this account (case-insensitive). |
| `-s <session>` | Only tokens in this session ID. |
| `-b <kind>` | `1` = primary, `2` = impersonation-level, `3` = delegation. |

### Actions

| Flag | Meaning |
|------|---------|
| `-c <program>` | Launch `<program>` with a matching token. |
| `-x <index>` | Use the token at `<index>` from the listed table. Requires `-c`. |
| `-t` | Prefer `CreateProcessWithTokenW` over `CreateProcessAsUserW`. |
| `-n` | Do not wait for the child process to exit. |

### Output

| Flag | Meaning |
|------|---------|
| `-l` | List accounts. In a console this opens the interactive menu. |
| `-e` | Extended static table: `#  ACCOUNT  TYPE  LEVEL  PID  SESSION`. |
| `--unique` | Aggregate by account instead of one row per token. |
| `--csv` | CSV to stdout (add `-e` for all columns). |
| `--json` | JSON to stdout (add `-e` for all columns). |

### Interactive

| Flag | Meaning |
|------|---------|
| `-i`, `--interactive` | Force the interactive menu (any listing mode). |
| `--nobridge` | Never use the local bridge; always launch directly. |
| `-P <n>`, `--port <n>` | Bridge listener port on `127.0.0.1` (default `4444`). |

### Other

| Flag | Meaning |
|------|---------|
| `-h`, `--help` | Show help. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | Usage / argument parsing error or invalid port. |
| `2` | No tokens matched the filters. |
| `3` | Missing privilege to launch a process. |
| `4` | Token found but process creation failed. |

## Interactive menu

```
TokenStealer v2 - Windows token enumerator / impersonator
Based on decoder-it/TokenStealer. Use only on systems you are authorized to test.

Use Up/Down to select a token, Enter to run a command, Esc to cancel.

     #    ACCOUNT
 >   1    D4\administrator
     2    Font Driver Host\UMFD-0
     3    NT AUTHORITY\SYSTEM
     ...
```

- **Up / Down** move the highlighted row.
- **PgUp / PgDn / Home / End** also navigate.
- **Enter** selects the account and then asks:

  ```
  Program to run [cmd.exe]:
  ```

  Press **Enter** on the empty line for the default `cmd.exe`, or type another
  program.
- **Esc** cancels.

What happens after you confirm depends on privileges and flags:

| `SeAssignPrimaryToken` | `--nobridge` | Result |
|---|---|---|
| held | either | Direct launch via `ExecuteWithToken` (no bridge). |
| not held | given | Direct launch via `ExecuteWithToken` (no bridge). |
| not held | not given | Local bridge on `127.0.0.1:<port>`. |

## Local bridge

When the impersonation path is used and the bridge is allowed, the tool:

1. Binds and listens on `127.0.0.1:<port>` (default `4444`) in a listener thread.
2. Launches a bridge child under the selected token:
   ```
   "<this exe>" --port <port> --bridge "<program>"
   ```
3. The child connects back, starts `<program>` with pipe-backed standard
   handles, and relays between the pipes and the socket.
4. The listener thread relays your console to the socket, so you interact with
   the program directly in the same window.

```
your console <-> listener socket <-> bridge child <-> pipes <-> program
```

This path uses `cmd.exe` or whatever you choose over pipes has no
console, so it may not print a banner or prompt — type a command and press Enter.
Type `exit` inside the shell to end it.

## Export

```bat
TokenStealer.exe -e --csv  > tokens.csv
TokenStealer.exe -e --json > tokens.json
```

`-e --csv` columns:

```csv
account,type,level,pid,session
D4\administrator,Primary,-,4,1
NT AUTHORITY\SYSTEM,Impersonation,Impersonation,812,0
```

`-e --json`:

```json
[
  {"account":"D4\\administrator","type":"Primary","level":"-","pid":"4","session":"1"}
]
```

Without `-e`, export contains the `account` column only, because `-l` collects
just account names.

## Examples

List every token the current user can see (opens the menu in a console):

```bat
TokenStealer.exe -l
```

Static extended table:

```bat
TokenStealer.exe -e
```

Aggregate by account:

```bat
TokenStealer.exe -l --unique
```

Only primary tokens:

```bat
TokenStealer.exe -e -b 1
```

Only tokens in process 100:

```bat
TokenStealer.exe -l -p 100
```

Interactive menu with a custom bridge port:

```bat
TokenStealer.exe -i -P 5555
```

Never use the bridge (direct launch only):

```bat
TokenStealer.exe -l --nobridge
```

Direct launch with `-c`:

```bat
TokenStealer.exe -u CORP\alice -c cmd.exe
TokenStealer.exe -u CORP\alice -c cmd.exe -t
```

Pick a token by its table index:

```bat
TokenStealer.exe -e
TokenStealer.exe -x 5 -c cmd.exe
```
<img width="1089" height="633" alt="image" src="https://github.com/user-attachments/assets/adbb94fe-800e-4e7b-8990-814c43a0f465" />

## Output columns

`-l` (and the interactive menu):

```
     #    ACCOUNT
```

`-e`:

```
     #    ACCOUNT        TYPE           LEVEL          PID     SESSION
```

- **TYPE** — `Primary` or `Impersonation`.
- **LEVEL** — for impersonation tokens: `Anonymous`, `Identification`,
  `Impersonation`, `Delegation`. Primary tokens show `-`.
- **PID** — owning process ID.
- **SESSION** — terminal session ID.

## Notes

- The bridge binds `127.0.0.1` only; nothing is exposed off-host.
- The chosen port must be free; otherwise the tool reports a `bind()` failure.
- The selected account must be able to read/execute the tool's EXE, because the
  bridge child is the same binary launched with `--bridge`.
- `--bridge` is an internal mode used by the child; you normally do not pass it
  yourself.
