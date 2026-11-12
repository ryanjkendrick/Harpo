# Moving Harpo to .NET 11

Status: plan, written 2026-10-31 against .NET 11 RC 3. .NET 11 became
generally available on 10 November 2026, and the facts below were re-checked
against GA on 11 November (see "Re-checked at GA"). Step 0 was done on
12 November on branch `feature/dotnet-11`: go, with D3 changed (see "Step 0
result").

## What the upgrade really is

Two changes travel together and cannot be separated:

1. **.NET 10 → .NET 11** across the runtime, ASP.NET Core, Blazor and
   EF Core 11.
2. **A new SQLite engine for the encrypted-database feature.**
   `Microsoft.Data.Sqlite.Core` 11 depends on SQLitePCLRaw.core 3.0.5. The
   package Harpo uses today for SQLCipher, `SQLitePCLRaw.bundle_e_sqlcipher`
   2.1.11, is a 2.x-only bundle that its maintainer has dropped; it does not
   work with SQLitePCLRaw 3. Microsoft's replacement of choice is
   **SQLite3 Multiple Ciphers** (`SQLite3MC.PCLRaw.bundle`). Every published
   version of that package (2.3.3 through 2.6.1) depends on SQLitePCLRaw.core
   3.0.x, so it cannot be adopted first on .NET 10 either. One step, both
   changes.

Everything else in .NET 11 is optional for Harpo and is deliberately kept out
of the migration release (see "Afterwards").

## Facts checked (2026-10-31)

| Fact | Source |
| --- | --- |
| `Microsoft.Data.Sqlite.Core` 11.0.0-rc.3 depends on `SQLitePCLRaw.core` 3.0.5 and targets `net10.0` only | package metadata on NuGet |
| `SQLite3MC.PCLRaw.bundle` 2.6.1 (SQLite3MC 2.6.1, SQLite 3.54.0) → `.provider` 2.6.1 → `SQLitePCLRaw.core` 3.0.2; same for 2.3.3–2.4.0 | package metadata on NuGet |
| `SQLite3MC.PCLRaw.lib` 2.6.1 ships natives for linux-x64, linux-arm64, linux-musl-x64/arm64, osx-x64/arm64, win-x64/arm64 and more | package contents |
| SQLite3MC opens SQLCipher 4 files with `Data Source=file:harpo.db?cipher=sqlcipher&legacy=4;Password=…`; `legacy` defaults to 0; the docs discourage legacy mode for *new* databases | SQLite3MC README and cipher docs |
| SQLite3MC supports `PRAGMA key`, `PRAGMA rekey` (encrypt a plain file, change key, or `rekey = ''` to decrypt); rekey in WAL mode since 2.4.0, salt cannot change in WAL mode; `PRAGMA key` succeeds even with a wrong key (check `sqlite_master`) | SQLite3MC pragma docs |
| **`sqlcipher_export()` is not documented by SQLite3MC** | SQLite3MC SQL-functions page |
| SQLCipher-scheme parameters with `legacy=4` match SQLCipher 4 defaults (PBKDF2-HMAC-SHA512, 256 000 iterations, HMAC-SHA512, 4096-byte pages) | SQLite3MC SQLCipher page |
| Blazor static SSR defers antiforgery validation to middleware; apps that call `app.UseAntiforgery()` need no change. Harpo calls it explicitly and validates `/logout` itself | aspnet/Announcements#535, Learn breaking-change page |
| .NET 11 adds a default cross-origin CSRF middleware judging `Sec-Fetch-Site`/`Origin` | same |
| Runtime Async is on by default for `net11.0` | What's new in .NET 11 |
| x64 floor rises to x86-64-v2 (SSE4.2, POPCNT, CX16); the runtime refuses to start on older CPUs. Linux Arm64 floor unchanged (armv8.0-a) | .NET 11 compatibility notes |
| EF Core 11: `Migrate()` throws when an assembly has no migrations (Harpo has them); the model snapshot now records the latest migration id; `dotnet ef` 11 needed | EF Core 11 what's-new and breaking changes |
| .NET 11 is STS; support projected to about November 2028, the same horizon as .NET 10 LTS | support policy |

## Re-checked at GA (2026-11-11)

Nothing above changed between RC 3 and GA.

| Fact | Source |
| --- | --- |
| .NET 11.0.0, SDK 11.0.100, released 2026-11-10 | .NET release metadata |
| `Microsoft.Data.Sqlite.Core` 11.0.0 still depends on `SQLitePCLRaw.core` [3.0.5, ) and targets `net10.0` only | package metadata on NuGet |
| `Microsoft.EntityFrameworkCore.Sqlite.Core`, `.Design`, `System.DirectoryServices.Protocols` and `dotnet-ef` 11.0.0 published 2026-11-10 | NuGet |
| `SQLite3MC.PCLRaw.bundle` is still 2.6.1 (2026-10-12) → `.provider` 2.6.1 → `SQLitePCLRaw.core` [3.0.2, ); `SQLitePCLRaw.bundle_e_sqlcipher` is still 2.1.11 with no 3.x | NuGet |
| `mcr.microsoft.com/dotnet/sdk:11.0` and `aspnet:11.0-resolute` exist for amd64, arm64 and arm; `aspnet:11.0` is the same image (Ubuntu 26.04.1, runtime 11.0.0), and `libldap2` 2.6.10 installs on it | the registry, and the image itself |
| 0.7 stays on .NET 10, which got its own security update the same day (10.0.15): 0.7.6 took the runtime, and #18 moves the 10.0 packages to 10.0.15 | .NET release metadata |

Prepared for step 0 on .NET 10, because they need the old build:

- `tests/Harpo.Tests/Fixtures/net10/`: database files written by the published
  0.7.6 image (`make.sh` remakes them): `plain/`, `encrypted/`, and
  `encrypted-wal/`, a file and its WAL copied while the site was frozen, so the
  sign-ins exist only in the WAL. `expected.txt` holds what SQLCipher 4 reads
  from each, and the key. These are the "file encrypted by the old SQLCipher
  build opens" test's input; the WAL one also checks that rows only in the WAL
  survive the new engine.
- `tests/e2e/measure-ui.sh` and the "before" figures for step 5, below.

## Decisions

**D1. One dedicated release, nothing else in it.** The migration ships as its
own version (call it 0.8.0) with no feature work and **no EF migration**.
Reason: a clean rollback. A 0.8.0 site can be put back on 0.7 by changing the
image tag, because the schema is identical and (see D2) the database file
format is too. Behaviour changes that need a minor version, such as removing
the `Auth:Ldap:AdminGroup` default, wait for a later release (see Afterwards).

**D2. Keep the SQLCipher 4 file format, now produced by SQLite3MC.** Every
connection opens with `cipher=sqlcipher&legacy=4`, for existing and new
files alike. Reasons: zero data conversion on upgrade, 0.7 can still open a
file 0.8 wrote (rollback), and the `sqlcipher` command-line tool keeps working
on backups. The cost is that SQLite3MC calls legacy mode "for compatibility
reasons only"; it is the same AES-256-CBC + HMAC-SHA512 construction, just
not their preferred one. Moving to ChaCha20-Poly1305 is a later, separate
release with a converter and a rollback story of its own.

**D3. Encrypt and decrypt through a copy made with `VACUUM INTO`; rotate with
`PRAGMA rekey`.** *(Changed by step 0; the plan was rekey in place for all
three.)* Harpo's path for "plaintext file found, key configured" made an
encrypted copy with `sqlcipher_export`, which SQLite3MC does not have, checked
it and swapped it in. The copy, the checks and the swap stay; only the copy is
now made with SQLite's own `VACUUM INTO`, to a `file:` URI carrying the scheme
and the key (`key=` empty for a plaintext copy; with no `key` at all the copy
keeps the source's key). `PRAGMA rekey` in place was tried first and rejected:
the full-disk suite stopped it part-way through encrypting, and SQLite3MC left
a file that opened neither with the key nor without, with no journal to roll
back. Rotation keeps `PRAGMA rekey`, which SQLite3MC rolls back cleanly when
it fails, and which now raises the failure instead of reporting success.

**D4. Do not enable Blazor auto-pause.** Pausing persists circuit state to the
browser; a vault page may hold a revealed password in that state. Off until
revealed secrets are cleared on pause, which is its own feature.

**D5. Runtime Async stays on** (the default). It is the one performance gain
worth having; the test matrix below is what makes it safe to take.

## Step 0, at GA: spike (branch `feature/dotnet-11`, not merged until step 1 passes)

Goal: a go/no-go with every surprise found before the real branch is cut.
Sub-agent sized work; a worktree; stage explicit paths. Uses GA packages.

1. Retarget both projects to `net11.0`; bump `Microsoft.EntityFrameworkCore.*`
   and `System.DirectoryServices.Protocols` to the GA 11.0.x; replace
   `SQLitePCLRaw.bundle_e_sqlcipher` with `SQLite3MC.PCLRaw.bundle` 2.6.1;
   keep `SQLitePCL.Batteries_V2.Init()` (the SQLite3MC bundle provides it).
2. Rewrite `DbEncryption` per D2/D3: connection string becomes a `file:` URI
   with `cipher=sqlcipher&legacy=4` plus `Password`; encrypt-in-place and
   decrypt through `PRAGMA rekey`; wrong-key detection keeps reading
   `sqlite_master`. `PRAGMA rekey` reports success on a full disk under SQLCipher,
   so `RekeyAsync` reopens the file to check; encrypting and decrypting need the
   same check once they use it, and the README's "second copy" wording and the
   export temp-file cleanup change with them. Re-test all three on a full volume.
   Rows only in the WAL must still survive, so keep the checkpoint that `ExportAsync`
   checks before anything is replaced. `EnsureEncryptionStateAsync` and
   `IsEncryptedAsync` call `File.Exists` on `DataSource`, which a `file:` URI would
   break, so they must keep getting the plain path; otherwise reconciliation is
   skipped and the Administration page shows "Unknown".
   Update the `DbEncryptionTests` and add two:
   *a file encrypted by the old SQLCipher build opens*, and *a file written by
   SQLite3MC opens in the old build* (interop both ways; the first reads the
   files in `tests/Harpo.Tests/Fixtures/net10/` and compares with its
   `expected.txt`; the second needs a
   small .NET 10 helper project, or the `sqlcipher` CLI from Homebrew, and
   can stay a manual check if that is simpler).
3. Fix whatever else fails to compile; run the unit suite in Release several
   times (the formerly flaky notes-scrub test is the canary for SQLite
   behaviour changes: it depends on free-list pages surviving until VACUUM).
4. Build the image on `sdk:11.0`/`aspnet:11.0-resolute` (keep the Ubuntu
   26.04 runtime base; at GA plain `11.0` is the same image, but the tag says
   which Ubuntu on purpose), confirm
   `libldap2` still installs on it and `docker scout quickview` is clean,
   then run the UI, session, offline and offline-disable e2e suites on a
   throwaway stack.
5. Measure: request latency and memory on the UI suite, before and after, on
   the same machine. This is the only place Runtime Async is evaluated.
   `tests/e2e/measure-ui.sh <image> 3` does it the same way both times. Before,
   on 2026-11-11 (published 0.7.6, .NET 10.0.15, Apple silicon, 10 CPUs and
   8 GB for Docker):

   | | 0.7.6 (.NET 10) |
   | --- | --- |
   | UI suite, three runs | 141.6 s, 141.5 s, 141.6 s |
   | Memory after a warm-up run | 252 MiB |
   | Memory during the runs | peak 299 MiB, 287 MiB at the end |
   | HTTP requests (circuit WebSocket left out) | 560; median 1.4 ms, p95 9.1 ms, max 22.2 ms |

   The suite's wall time hardly moves, because its own waits set it, so the
   request times and memory are the figures to compare. Clicks inside a page
   travel over the circuit and aren't in the request log; a slowdown there
   would show up as a longer suite.
6. Check the two behaviours that could change silently:
   - the audit log's client address (flows through `IHttpContextAccessor`,
     an `AsyncLocal`, which Runtime Async handles differently when no
     ambient state exists): the proxy test's `password.reveal` row must
     still show the client address;
   - replication pulls and the offline snapshot endpoint under the new
     cross-origin CSRF middleware (server-to-server requests carry no
     `Origin`): the two-site stack must still sync, and `session.e2e.js`
     must still pass.
7. Write down the result: what changed, what broke, timings, and the list of
   follow-ups for "Afterwards". If interop in step 2 fails in either
   direction, stop and rethink D2 before going further.

## Step 0 result (2026-11-12)

Go. Branch `feature/dotnet-11`, on develop after 0.7.8. SDK 11.0.100 (the
Homebrew `dotnet-sdk` cask), runtime 11.0.0, SQLite3MC 2.6.1 (SQLite 3.54.0).

What changed:

- Both projects target `net11.0`; EF Core, `Microsoft.Data.Sqlite` and
  `System.DirectoryServices.Protocols` 11.0.0; `SQLite3MC.PCLRaw.bundle`
  2.6.1 replaces `SQLitePCLRaw.bundle_e_sqlcipher`; `Batteries_V2.Init()`
  unchanged. `dotnet-ef` 11.0.0; CI and release workflows on `11.0.x`; the
  Dockerfile on `sdk:11.0` and `aspnet:11.0-resolute`. No code outside
  `DbEncryption` needed changing to compile.
- The scheme can only be set per connection: `sqlite3mc_config` refuses to
  change process-wide defaults (it returns -1 without a connection). So every
  keyed connection string comes from `DbEncryption.KeyedConnectionString` or
  `ApplyKey`, which turn the Data Source into
  `file:<path>?cipher=sqlcipher&legacy=4`. A bare `Password=` gets SQLite3MC's
  default (ChaCha20), which cannot read Harpo's files: a test checks exactly
  that. `DbEncryption.FilePath` gives the plain path back for everything that
  looks at the file (the lock file, `DbInitializer`'s folder, `File.Exists`).
- D3 as changed above.
- Keys are quoted in C# for `PRAGMA key`/`rekey`: a `SELECT quote()` before
  the key reads the encrypted schema and fails under SQLite3MC.
- With a hot journal, a wrong key is reported as error 11 (damaged), not 26;
  the journal is left alone and the right key rolls it back. `CanOpenAsync`
  treats 11 with a hot journal as "this key does not fit".
- SQLite3MC is compiled with `SECURE_DELETE`, `DEFAULT_FOREIGN_KEYS`,
  `DEFAULT_RECURSIVE_TRIGGERS` and `DEFAULT_AUTOVACUUM`. Foreign keys were
  already on (EF), Harpo has no triggers, and auto-vacuum applies to new files
  only (0.7 opens them). Secure delete zeroes freed pages: the purge scrub
  stays (it is about the WAL and files 0.7 wrote) and its tests now play 0.7's
  writes with secure delete off.

Interop, both ways: SQLite3MC reads the three files 0.7.6 wrote
(`Fixtures/net10`, including rows only in the WAL), and the `sqlcipher` 4.6.1
tool reads files the .NET 11 build created, encrypted (`VACUUM INTO`) and
rekeyed (`cipher_integrity_check` clean). Rollback: the published 0.7.8 ran
on an encrypted volume written by the .NET 11 build, and on a plain volume the
.NET 11 build had just encrypted, and replicated with .NET 11 peers; the
session suite passed on both.

Tests: unit suite 578, three Release runs green, in about 1 min 10 s (1 min
55 s on .NET 10). UI 76/76 on an encrypted and a plain site, session 9/9 on
two, offline 22/22, offline-disable 10/10 (on a fresh site; run straight after
the offline suite on the same site it times out on both 0.7.8 and 11, which is
the suite, not the runtime), database lock 83/83, full disk 72/72 (it failed
5 with rekey in place). Three sites replicated throughout. Docker Scout clean;
`libldap2` 2.6.10 installs; the image is Ubuntu 26.04.1.

Behaviours that could change silently (step 6): behind nginx with forwarded
headers, `password.reveal`, `offline.sync` and `entry.delete` record the
client's address, not the proxy's, the same as 0.7.8; replication pulls and
the offline snapshot pass the new cross-origin middleware.

Measured (step 5), same machine and script as the baseline:

| | 0.7.6 (.NET 10) | .NET 11 build |
| --- | --- | --- |
| UI suite, three runs | 141.6 s, 141.5 s, 141.6 s | 142.1 s, 141.6 s, 141.6 s |
| Memory after a warm-up run | 252 MiB | 232 MiB |
| Memory during the runs | peak 299 MiB, 287 MiB at the end | peak 269 MiB, 269 MiB at the end |
| HTTP requests | 560; median 1.4 ms, p95 9.1 ms, max 22.2 ms | 561; median 1.2 ms, p95 8.6 ms, max 64.2 ms |

One request of 561 took 64 ms; the rest are faster than on .NET 10.

Follow-ups, none for 0.8.0:

- New Blazor analysers report `BL0012` (a `StateHasChanged` call that is not
  needed) in `Admin.razor`, `Vault.razor` and `ImportDialog.razor`, and `BL0016`
  (a JS interop call without try/catch) in `GroupDetail.razor`, `Vault.razor`
  and `Pager.razor`. Warnings only; look at them in their own change.
- The offline-disable suite should wait out the offline-sync limit when it
  follows the offline suite.
- Step 1 still owes: `global.json`, the AD lab, the nginx and Caddy examples,
  amd64 under emulation, upgrade from 0.7.0, README and release notes.

## Step 1: the real branch

1. Rebase the spike onto `develop`, confirm every package is at its GA version, bump
   `dotnet-ef` in `dotnet-tools.json`, `dotnet-version: "11.0.x"` in
   `.github/workflows/release.yml`, and the two `FROM` lines in the
   Dockerfile. Consider adding a `global.json` pinning the 11.0 SDK so local
   builds and CI agree.
2. Run `dotnet ef migrations has-pending-model-changes` under EF 11 before
   touching the model; a false positive here means the snapshot format
   change needs a snapshot-only regeneration, which is fine as long as no
   migration is added.
3. Full matrix, all on throwaway stacks, never the demo or the AD lab until
   the end:
   - unit suite, Release, three runs;
   - UI 64, session 9, offline 22, offline-disable 10;
   - **upgrade in place, unencrypted volume:** 0.7.0 → candidate, data
     intact, sessions require one sign-in only if the cookie format changed
     (it should not);
   - **upgrade in place, encrypted volume:** 0.7.0 with `Harpo__DatabaseKey`
     → candidate opens it unchanged; then **rollback:** the same volume
     opened again by 0.7.0 (this is D2's promise);
   - key rotation and `Harpo__RemoveDatabaseEncryption` on the candidate;
   - **mixed versions:** 0.7.0 peer ↔ candidate peer replicating both ways,
     including an encrypted site on each side;
   - AD lab against the candidate image (LDAP natives, "Who am I?",
     revalidation with the service account);
   - the nginx and Caddy proxy examples once each;
   - both architectures: pull the multi-arch candidate on the Mac (arm64) and
     run it under `--platform linux/amd64` once for a smoke test.
4. Documentation: README (SQLite3MC replaces SQLCipher as the engine, the
   file format is unchanged, the x86-64-v2 CPU floor, Development section's
   SDK version), the release checklist in memory, the Docker Hub overview.
5. Release notes must say, in this order: nothing to do for most sites; the
   image needs a CPU with SSE4.2 (any x64 server made after about 2009, any
   Arm64); encrypted databases keep working and keep their format; rollback
   to 0.7 is supported by changing the tag back; the engine behind
   `Harpo__DatabaseKey` is now SQLite3 Multiple Ciphers; no schema migration.

## Step 2: release 0.8.0

Follow the release checklist: compose pin to `:0.8` in its own commit, merge
to `main`, tag, workflow, verify the cold-pulled image with the UI and
session suites plus the published 0.7.0 → 0.8.0 upgrade (both an unencrypted
and an encrypted volume), GitHub release, Hub overview to the user, develop
fast-forwarded, throwaways removed, demo and AD lab moved to the release.

## Afterwards (each its own feature, none in 0.8.0)

- Remove the `Auth:Ldap:AdminGroup` default in its own minor release (0.9.0):
  take `"AdminGroup": "Harpo Admins"` out of `src/Harpo/appsettings.json`,
  because a short name matches a group of that name in any OU, so nobody
  should get it without asking for it. Blank already means no site admins, and
  short names set on purpose keep working, with the warning from 0.7.5. The
  release notes must lead with the one action: an LDAP site that relies on the
  default has no site admins until it sets one. Going back to 0.8 only brings
  the default back.
- `CloseOnAuthenticationExpiration` and `WithBrowserOptions` for the server
  circuit; possibly retire parts of the hand-written reconnect script.
- Convert encrypted databases from the SQLCipher scheme to ChaCha20-Poly1305
  with a one-time converter, a marker so each file's scheme is known, and a
  rollback plan; only after 0.8 has been out for a while.
- C# 15 union types for `DirectoryLookup` and revalidation results.
- Decide on auto-pause once revealed state is cleared on pause (D4).
- Re-check the SQLite3MC release cadence twice a year; it is the component
  Microsoft pointed to, but it is one maintainer's project, as SQLCipher's
  bundle was.

## Risks

| Risk | How the plan handles it |
| --- | --- |
| SQLite3MC's legacy=4 output is not byte-compatible with real SQLCipher 4 | Interop test both ways in step 0; if it fails, D2 is reconsidered before GA |
| `PRAGMA rekey` behaves differently from `sqlcipher_export` | Found in step 0: in place, a full disk part-way through encrypting ruins the file. Encrypt and decrypt use a checked `VACUUM INTO` copy instead (D3); the full-disk suite covers it |
| Runtime Async changes `AsyncLocal` flow or exception shapes | Audit client-address check and three Release runs of the unit suite |
| New cross-origin CSRF middleware blocks server-to-server or offline requests | Two-site replication and offline suites in the matrix |
| A site runs on a pre-2009 x64 CPU | Release notes name the floor; the runtime refuses to start with a clear message rather than misbehaving |
| The facts above were checked against RC 3 | Re-check the package graph (SQLitePCLRaw versions, SQLite3MC compatibility) on GA day before step 0 |
| SQLite 3.54 changes free-list or WAL behaviour the notes-scrub test relies on | That test is run first and often in step 0 |
