# Moving Harpo to .NET 11

Status: plan, written 2026-10-31 against .NET 11 RC 3. .NET 11 became
generally available on 10 November 2026, and the facts below were re-checked
against GA on 11 November (see "Re-checked at GA"). Step 0 starts once the
11.0 SDK is installed on the development machine; the Homebrew formula there
was still 10.0.403 on 11 November.

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

**D3. Encrypt-in-place via `PRAGMA rekey`, not `sqlcipher_export`.** Harpo's
current path for "plaintext file found, key configured" attaches an encrypted
target and calls `sqlcipher_export`, which SQLite3MC does not document. The
replacement is what SQLite3MC documents: open the plain file, `PRAGMA rekey`
with the key. The same primitive already does key rotation, and `rekey = ''`
does the explicit decrypt. The export-to-temp-file code goes away. Checkpoint
and switch the file out of WAL mode around the rekey, because the docs forbid
a salt change in WAL mode.

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
| `PRAGMA rekey` behaves differently from `sqlcipher_export` on a WAL file | Checkpoint and leave WAL around the rekey; `DbEncryptionTests` cover each transition |
| Runtime Async changes `AsyncLocal` flow or exception shapes | Audit client-address check and three Release runs of the unit suite |
| New cross-origin CSRF middleware blocks server-to-server or offline requests | Two-site replication and offline suites in the matrix |
| A site runs on a pre-2009 x64 CPU | Release notes name the floor; the runtime refuses to start with a clear message rather than misbehaving |
| The facts above were checked against RC 3 | Re-check the package graph (SQLitePCLRaw versions, SQLite3MC compatibility) on GA day before step 0 |
| SQLite 3.54 changes free-list or WAL behaviour the notes-scrub test relies on | That test is run first and often in step 0 |
