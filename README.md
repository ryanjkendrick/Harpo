# 🤫 Harpo

A simple self-hosted team password manager, named after **Harpocrates** — the god
of silence and secrets.

Built with **ASP.NET Core + Blazor** (interactive server rendering), authenticated
against **Active Directory**, shipped as a **Docker** container, with built-in
**cross-site replication**.

## Features

- **Active Directory sign-in** — users log in with their AD credentials via a
  direct LDAP(S) bind from the app; membership of a configurable AD group grants
  site-admin rights. Works from Linux containers (no domain-joined host needed).
- **Groups gate access** — passwords live inside groups, and only users who have
  been added to a group can see its passwords. Group admins manage membership;
  any user can create a group and becomes its admin.
- **Named, decorated entries** — every password has a name, an icon, the URL it
  belongs to, an account username, and free-text notes.
- **Full password history** — every password change is an immutable revision
  recording *who* changed it and *when*; old values remain viewable.
- **Cross-site replication** — multiple sites (offices, datacenters) each run
  their own Harpo with their own database and continuously merge changes, AD-style.
- **Encrypted at rest** — password values are AES-256-GCM encrypted under a
  master key that never lives in the database.
- **Audit log** — who revealed, copied, or deleted what, when, from where;
  append-only, replicated to every site, browsable by site admins, with
  configurable retention — and an admin kill switch.
- **Installable PWA with an offline vault** — users can keep an encrypted,
  passphrase-protected, read-only copy of their passwords on their device for
  when the server (or the network) is down. Admins can forbid this org-wide
  with one Docker environment variable.

## Quick start — two-site replication demo

Requires only Docker. Authentication runs in built-in dev mode (no AD needed):

```bash
git clone https://github.com/ryanjkendrick/Harpo.git
cd Harpo
docker compose -f docker-compose.multisite.yml up -d --build
```

- Site **alpha**: <http://localhost:8081>
- Site **beta**: <http://localhost:8082>
- Sign in as `alice` / `alice` (site admin) or `bob` / `bob`.

Create a group and a password on alpha, then open beta — within a few seconds the
same data is there. The **Administration** page on each site shows peer health and
the replication high-watermark vector.

## Testing real AD logins — the Samba AD lab

To exercise the genuine LDAP code path (bind, `sAMAccountName` lookup, `memberOf`
→ site-admin mapping) without touching a real domain controller, the repo ships a
lab compose file with a **Samba Active Directory DC**:

```bash
docker compose -f docker-compose.adtest.yml up -d --build
```

The first start provisions a throwaway `HARPO.LAB` domain (takes a minute; the
Harpo container waits for the DC's healthcheck). Then open <http://localhost:8083>
and sign in with a *directory* account:

| Account | Password | Directory state | Result in Harpo |
| --- | --- | --- | --- |
| `ada` | `Passw0rd!` | member of the **Harpo Admins** AD group | site admin |
| `grace` | `Passw0rd!` | regular user | normal user |

Harpo here runs in real `Ldap` mode — the only lab-ism is
`SkipCertificateValidation` for the DC's self-signed certificate. On Linux that
switch works by setting `LDAPTLS_REQCERT=never` (libldap handles TLS and ignores
the .NET certificate callback); with a real DC, leave it off and trust the DC's
certificate properly. The domain data persists in the `samba-data`/`samba-etc`
volumes; `docker compose -f docker-compose.adtest.yml down -v` resets the lab.
Manage lab users with the usual tooling, e.g.:

```bash
docker exec harpo-samba-ad samba-tool user create casey 'Passw0rd!' --given-name=Casey
```

## Production deployment (single site, Active Directory)

1. Generate a master key and put it in `.env` next to `docker-compose.yml`:

   ```bash
   echo "HARPO_MASTER_KEY=$(openssl rand -base64 32)" > .env
   ```

2. Edit the `Auth__Ldap__*` values in `docker-compose.yml` for your domain.

3. Start it:

   ```bash
   docker compose up -d --build
   ```

4. Put a TLS-terminating reverse proxy (Caddy, nginx, Traefik, IIS ARR) in front
   of port 8080. The app serves plain HTTP and expects the proxy to handle HTTPS;
   set `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` in the container environment so
   redirects and secure cookies respect `X-Forwarded-Proto`.

> **Back up two things:** the `/data` volume (database + cookie keys) and the
> master key. Ciphertext without the master key is gone forever.

### Keys from Docker secrets

Every configuration value also accepts a `__File` variant pointing at a file,
so keys can come from Docker/Kubernetes secrets instead of environment
variables (which leak via `docker inspect` and process listings):

```yaml
services:
  harpo:
    environment:
      Harpo__MasterKey__File: /run/secrets/harpo_master_key
    secrets:
      - harpo_master_key
secrets:
  harpo_master_key:
    file: ./secrets/master_key.txt
```

The file's content (trimmed) becomes the value; this works for
`Harpo__DatabaseKey`, `Replication__Key`, and any other key. A configured
secret file that doesn't exist fails startup loudly rather than silently
running with an empty key.

### Active Directory settings

| Setting | Meaning | Example |
| --- | --- | --- |
| `Auth__Ldap__Server` | Domain controller host | `dc01.corp.example.com` |
| `Auth__Ldap__Port` | LDAP port | `636` |
| `Auth__Ldap__UseSsl` | Use LDAPS (strongly recommended — plain LDAP sends the bind password in clear text) | `true` |
| `Auth__Ldap__SkipCertificateValidation` | Accept any DC certificate (labs only) | `false` |
| `Auth__Ldap__UpnSuffix` | Appended when users type a bare account name, so `jsmith` binds as `jsmith@corp.example.com` | `corp.example.com` |
| `Auth__Ldap__SearchBase` | Where to look up the user's display name and groups | `DC=corp,DC=example,DC=com` |
| `Auth__Ldap__AdminGroup` | AD group (CN or full DN) whose members are Harpo **site admins** — they see and manage every group | `Harpo Admins` |

Users sign in with their own AD credentials; Harpo performs a simple bind **as
the user** to validate them, then reads `displayName` and `memberOf` from their
directory entry. No service account is required. Inside Harpo, people are
identified by their `sAMAccountName` — that's the username group admins type
when adding members.

## Offline access (PWA)

Harpo is an installable PWA (browser "Install app" / add-to-home-screen), and
ships an optional **offline vault**: a read-only copy of the passwords a user
can see, stored on their device encrypted under an *offline passphrase* they
choose. Reachable from the sidebar ("Offline vault") or `/offline.html`.

How it works, honestly:

- While online and signed in, the device downloads the user's entries from
  `/api/offline/snapshot` (an audited, rate-limited bulk decrypt, scoped to the
  groups the user is **an explicit member of** — site admins don't get an
  everything-snapshot).
- The browser re-encrypts the snapshot locally with WebCrypto — a random
  AES-256-GCM data key wrapped by a key derived from the offline passphrase
  (PBKDF2-SHA256, 600k iterations) — and stores it in IndexedDB. **The server's
  master key never reaches the device.**
- Offline, the passphrase unlocks a read-only list with search, reveal, and
  copy. No editing — writes always happen online against the server.
- Snapshots expire after `SnapshotMaxAgeDays` (default 7) without a refresh;
  expired copies refuse to unlock until the device syncs again. The vault also
  auto-locks after 10 minutes of inactivity.

The admin switch, in any compose file / environment:

```yaml
Harpo__Offline__Enabled: "false"   # forbid offline password storage org-wide
```

Disabling it hides the feature, turns the snapshot API dark (404), and makes
devices **wipe their local copy the next time they contact the server**. Be
honest about the physics: a device that never reconnects keeps its encrypted
copy until it expires — no server can remotely erase a disconnected laptop.
That copy is protected by the user's passphrase (and their disk encryption),
which is exactly the trade-off you accept by enabling offline access. The
demo stacks show both settings: multisite has it on, the AD lab has it off.

Also worth knowing: the service worker only ever caches the static offline
page and PWA assets — never authenticated pages or API responses. On iOS,
the OS may evict PWA storage under disk pressure; treat the offline copy as
disposable (it re-syncs on the next online visit).

## Cross-site replication

Each site runs its own container and database, so every site keeps working when
links between sites are down. Replication is modeled on AD's own USN scheme:

- Every row carries `(OriginSiteId, OriginSeq)` — the site that last wrote it and
  that site's monotonically increasing change number.
- Every site keeps a **high-watermark vector**: the highest sequence it has seen
  from each origin. On a timer it sends that vector to each peer, which replies
  with only the rows the caller hasn't seen.
- Conflicts resolve **last-writer-wins** (timestamp, with a deterministic
  tie-break), so all sites converge to identical data. Password revisions are
  append-only, which means *concurrent password changes on two sites both survive
  in history* — the newer one becomes current.
- Deletes are tombstones, so they replicate like any other change.
- Rows keep their origin stamps as they spread, so changes flow **transitively**:
  in a chain `A ↔ B ↔ C`, A's changes reach C through B without A and C ever
  talking. Any connected topology works; you don't need a full mesh.

To connect sites, give every site: a **unique** `Harpo__SiteId`, the **same**
`Harpo__MasterKey`, the **same** `Replication__Key`, and one or more peers:

```yaml
Harpo__SiteId: "london"
Harpo__MasterKey: "…same everywhere…"
Replication__Key: "…same everywhere…"
Replication__Peers__0__Name: "sydney"
Replication__Peers__0__Url: "https://harpo.sydney.example.com"
Replication__Peers__1__Name: "newyork"
Replication__Peers__1__Url: "https://harpo.newyork.example.com"
```

Peer URLs point at the same web app; peers authenticate to each other with the
shared `Replication__Key` header, so site-to-site traffic must run over HTTPS
(or a private tunnel/VPN). A brand-new empty site pointed at a peer performs a
full initial sync automatically.

Operational notes:

- Keep site clocks NTP-synced — last-writer-wins uses timestamps (AD has the
  same requirement).
- Site ids are forever: don't reuse a site id with an empty database *unless*
  you first let it fully sync from a peer (it then continues its old sequence
  automatically; the code handles this recovery case).
- Adding a site later: start it empty with a new id and a peer — done.

## Encrypting the database file

Password *values* are always AES-256-GCM encrypted, but the rest of the SQLite
file (entry names, URLs, usernames, membership) is plaintext by default —
protect it with disk encryption and encrypted backups, or turn on **full-file
encryption** (SQLCipher):

```yaml
Harpo__DatabaseKey: "…per-site secret…"
```

- **Existing databases are migrated automatically**: on the next start Harpo
  detects a plaintext file and encrypts it in place (and cleans up the WAL
  sidecar files, which would otherwise still hold plaintext pages).
- The key is **per-site** — unlike the master key it does not need to match
  other sites, and replication is completely unaffected.
- **Rotate keys** by setting `Harpo__PreviousDatabaseKey` to the old key next
  to the new `Harpo__DatabaseKey` for one start (the file is rekeyed in place;
  then remove the previous key from configuration).
- **Remove encryption** deliberately by adding
  `Harpo__RemoveDatabaseEncryption: "true"` alongside the current key for one
  start. A missing or wrong key never silently falls back — Harpo refuses to
  start with a clear error instead.

Be clear about what this buys: it protects *copied files* — stolen volumes,
disk images, careless backups. An attacker on the live host can read the key
from the container environment, exactly like the master key. It is defence in
depth, not a new trust boundary. (Implementation: the bundled SQLite is the
SQLCipher community build, which behaves identically to stock SQLite when no
key is configured.)

## Audit log

Harpo records the events that matter for a password manager — the ones no other
record captures:

| Action | Recorded when |
| --- | --- |
| `password.reveal` / `password.copy` | someone views or copies a current password |
| `revision.reveal` | someone views a historical password value |
| `offline.sync` | a device downloads an offline snapshot (a bulk decrypt) |
| `entry.delete` / `group.delete` | something is deleted |
| `member.add` / `member.remove` / `member.role` | group access changes |

Each event stores who, when, what (denormalized names, so the trail outlives
renames and deletions), the site it happened on, and a best-effort client
address. Events are **append-only and replicate between sites** like password
revisions, so every site's admins see the whole organisation's trail on the
**Administration** page (filterable, newest first).

Controls:

```yaml
Harpo__Audit__Enabled: "false"     # stop recording on this site
Harpo__Audit__RetentionDays: "90"  # hard-delete older events (default 365; 0 = keep forever)
```

The toggle governs *recording on that site*; events already recorded (or
replicated from other sites) remain visible. Retention purges run daily per
site. Recording is fail-open by design: an audit-write failure is logged loudly
but never blocks the user's operation. Password *changes* aren't audit events —
they're already permanently attributed in each entry's revision history.

## Configuration reference

All settings can be given as environment variables (`Section__Key` form).

| Setting | Default | Meaning |
| --- | --- | --- |
| `ConnectionStrings__Harpo` | `Data Source=harpo.db` (image: `/data/harpo.db`) | SQLite database location |
| `Harpo__SiteId` | `default` | Unique, stable id of this site |
| `Harpo__MasterKey` | *(required)* | Base64 32-byte key or passphrase; encrypts passwords at rest; identical on all sites |
| `<AnyKey>__File` | — | Read the value of `<AnyKey>` from this file (Docker/K8s secrets) |
| `Harpo__DatabaseKey` | *(empty = off)* | Optional SQLCipher key encrypting the whole database file; per-site |
| `Harpo__PreviousDatabaseKey` | — | Set for one start (with a new `DatabaseKey`) to rotate the file key |
| `Harpo__RemoveDatabaseEncryption` | `false` | Set `true` for one start (with the current key) to decrypt the file |
| `Harpo__DataProtectionKeysPath` | *(image: `/data/keys`)* | Where cookie/antiforgery keys persist |
| `Harpo__Audit__Enabled` | `true` | Record audit events (reveals, copies, deletions, membership changes) on this site |
| `Harpo__Audit__RetentionDays` | `365` | Hard-delete audit events older than this (0 = keep forever) |
| `Harpo__Offline__Enabled` | `true` | Allow devices to keep an encrypted offline copy of their user's passwords |
| `Harpo__Offline__SnapshotMaxAgeDays` | `7` | Max age of an offline copy before it must refresh from the server |
| `Auth__Mode` | `Ldap` | `Ldap` or `Development` |
| `Auth__DevUsers__N__*` | — | Dev-mode users (`Username`, `Password`, `DisplayName`, `IsSiteAdmin`) |
| `Auth__Lockout__Enabled` | `true` | Brute-force lockout on the sign-in form |
| `Auth__Lockout__MaxFailuresPerAccount` | `5` | Failures against one account before it is blocked |
| `Auth__Lockout__MaxFailuresPerIp` | `20` | Failures from one address (any accounts) before it is blocked |
| `Auth__Lockout__WindowMinutes` | `15` | How long failures keep counting |
| `Auth__Lockout__LockoutMinutes` | `5` | How long a block lasts |
| `Replication__Key` | *(empty = replication off)* | Shared secret between sites |
| `Replication__IntervalSeconds` | `15` | How often to pull from peers |
| `Replication__BatchSize` | `2000` | Max rows per origin per pull |
| `Replication__Peers__N__Name/Url` | — | Peer sites to pull from |

## Security model (read this)

- Passwords are encrypted with AES-256-GCM before hitting the database; the
  master key comes from configuration/environment only. Anyone with both the
  database *and* the key can read secrets — protect the key like a domain admin
  password (Docker secrets, a vault, or locked-down env files). Optionally the
  whole database file can be SQLCipher-encrypted too (`Harpo__DatabaseKey`) so
  copied files and backups expose no metadata either — see "Encrypting the
  database file".
- Decryption happens **server-side, on explicit reveal/copy actions only**, and
  every reveal is authorization-checked against group membership. This is a
  *trusted-server* design, matching its role as an internal team tool — it is
  not a zero-knowledge/client-side-crypto product.
- All access control is enforced in the service layer, not the UI.
- The AD bind sends the user's password to the DC — use LDAPS (`UseSsl=true`).
  Failed logins are logged; invalid and unreachable-DC cases are distinguished.
- **Brute-force lockout** is on by default: 5 failures against an account (or 20
  from one address across any accounts) within 15 minutes blocks further
  attempts for 5 minutes — tune via `Auth__Lockout__*`. Only *failures* count;
  an unreachable DC does not. While blocked, attempts never reach the
  authenticator, so a password spray also stops generating LDAP binds against
  your domain controllers (and stops feeding AD's own account-lockout counter).
  Inherent trade-off of any lockout: someone who knows a username can
  nuisance-block that account's Harpo sign-in for the lockout period. Behind a
  reverse proxy, set `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` so the
  per-address limit sees real client IPs rather than the proxy's.
- `Auth__Mode=Development` is for demos and local hacking only. The app logs a
  loud warning at startup while it's active.
- Run the web UI behind HTTPS. The clipboard API also requires a secure context,
  so copy buttons work best over HTTPS (a legacy fallback covers plain HTTP).

## Development

```bash
dotnet run --project src/Harpo    # dev profile: dev users alice/alice, bob/bob
dotnet test                       # 31 tests: crypto, authz, replication
```

The dev profile (`appsettings.Development.json`) uses a local SQLite file, dev
auth, and a throwaway master key.

## Design notes & limitations

- **SQLite, one writer** — each site's container owns its database file; scale-out
  within a site (multiple replicas of one site) is not supported. Multiple
  *sites* are the scaling model.
- **Schema** is managed with EF Core migrations, applied automatically at
  startup. Databases created by older Harpo versions (pre-migrations) are
  baselined automatically on first start. When upgrading a replicated
  deployment, upgrade sites one at a time; the replication protocol tolerates
  peers that don't yet know about newer tables.
- **LWW granularity** is per row (per entry metadata / per membership); password
  values themselves never conflict because revisions are append-only.
- **Deleting a group** tombstones the group; its entries stop being visible
  everywhere but their ciphertext and history remain in the database.
- Blazor interactive server rendering keeps secrets and crypto on the server;
  revealed passwords transit the SignalR websocket (over your HTTPS).
