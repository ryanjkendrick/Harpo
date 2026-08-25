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

## Configuration reference

All settings can be given as environment variables (`Section__Key` form).

| Setting | Default | Meaning |
| --- | --- | --- |
| `ConnectionStrings__Harpo` | `Data Source=harpo.db` (image: `/data/harpo.db`) | SQLite database location |
| `Harpo__SiteId` | `default` | Unique, stable id of this site |
| `Harpo__MasterKey` | *(required)* | Base64 32-byte key or passphrase; encrypts passwords at rest; identical on all sites |
| `Harpo__DataProtectionKeysPath` | *(image: `/data/keys`)* | Where cookie/antiforgery keys persist |
| `Harpo__Offline__Enabled` | `true` | Allow devices to keep an encrypted offline copy of their user's passwords |
| `Harpo__Offline__SnapshotMaxAgeDays` | `7` | Max age of an offline copy before it must refresh from the server |
| `Auth__Mode` | `Ldap` | `Ldap` or `Development` |
| `Auth__DevUsers__N__*` | — | Dev-mode users (`Username`, `Password`, `DisplayName`, `IsSiteAdmin`) |
| `Replication__Key` | *(empty = replication off)* | Shared secret between sites |
| `Replication__IntervalSeconds` | `15` | How often to pull from peers |
| `Replication__BatchSize` | `2000` | Max rows per origin per pull |
| `Replication__Peers__N__Name/Url` | — | Peer sites to pull from |

## Security model (read this)

- Passwords are encrypted with AES-256-GCM before hitting the database; the
  master key comes from configuration/environment only. Anyone with both the
  database *and* the key can read secrets — protect the key like a domain admin
  password (Docker secrets, a vault, or locked-down env files).
- Decryption happens **server-side, on explicit reveal/copy actions only**, and
  every reveal is authorization-checked against group membership. This is a
  *trusted-server* design, matching its role as an internal team tool — it is
  not a zero-knowledge/client-side-crypto product.
- All access control is enforced in the service layer, not the UI.
- The AD bind sends the user's password to the DC — use LDAPS (`UseSsl=true`).
  Failed logins are logged; invalid and unreachable-DC cases are distinguished.
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
- **Schema** is created with `EnsureCreated` for simplicity; moving to EF
  migrations is the natural next step before schema-evolving upgrades.
- **LWW granularity** is per row (per entry metadata / per membership); password
  values themselves never conflict because revisions are append-only.
- **Deleting a group** tombstones the group; its entries stop being visible
  everywhere but their ciphertext and history remain in the database.
- Blazor interactive server rendering keeps secrets and crypto on the server;
  revealed passwords transit the SignalR websocket (over your HTTPS).
