# GeoIP: sign-in locations

When a member signs in to the member portal (or an administrator to the
console) with their wallet, the wallet shows them where the sign-in request
came from — the `requester.location` of `auth/oob` step 2, for example
`Vienna, AT`. The VTC works that out from the requesting browser's address
with a **local database file only**. It never calls a third-party service
(base design §12.6), so the address never leaves the VTC.

Without a database every location is `unknown`, which the wallet shows as a
warning rather than as neutral. Configuring one is optional, but recommended.

## What it shows

- `City, CC` — the English city name and the ISO 3166-1 country code
  (`London, GB`, `Frankfurt am Main, DE`).
- The English country name alone (`Sweden`) when the record has no city.
- `unknown` when no database is loaded, the database has no record for the
  address, or the address is not a public one: private (`10/8`,
  `172.16/12`, `192.168/16`), loopback, link-local, carrier-grade NAT
  (`100.64/10`), IPv6 unique-local (`fc00::/7`), documentation, benchmarking,
  multicast and reserved ranges are never looked up. A VTC behind a reverse
  proxy must see the client's address, not the proxy's, for this to say
  anything.

The result is at most 128 characters, the limit the `auth/oob` schema sets.
Only that coarse result is kept (in the sign-in request and its
`MemberWalletSignIn` / `AdminWalletSignIn` audit rows); the lookup logs and
stores nothing about the address.

## Choosing a database

Any MaxMind DB (`.mmdb`) file with the GeoIP2 **City** record layout works.
Two free ones:

| Database | Licence | Notes |
|---|---|---|
| **DB-IP "IP to City Lite"** (recommended) | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — attribution required | Direct download, no account. Updated monthly. |
| MaxMind **GeoLite2 City** | [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) | Needs a free MaxMind account and licence key. Updated twice weekly. |

### DB-IP City Lite

The file for a month is
`https://download.db-ip.com/free/dbip-city-lite-YYYY-MM.mmdb.gz`
(about 60 MB compressed, 130 MB unpacked):

```sh
sudo mkdir -p /var/lib/vtc/geoip
cd /var/lib/vtc/geoip
curl -fsSLo dbip-city-lite.mmdb.gz \
  "https://download.db-ip.com/free/dbip-city-lite-$(date -u +%Y-%m).mmdb.gz"
gunzip -f dbip-city-lite.mmdb.gz        # → dbip-city-lite.mmdb
```

**Attribution.** DB-IP Lite is licensed under CC BY 4.0, which requires
crediting DB-IP wherever the data is used. Their requested form is:

> IP Geolocation by [DB-IP](https://db-ip.com)

The VTC does not display this for you. Places an operator could carry it, if
they wish: the community website's footer or an "about" / "legal" page (the
website is the operator's own content — see
[Website + admin UX](website-and-admin.md)), a customised member portal served
from `admin_ui.members_dir`, or the community's published privacy notice.

### MaxMind GeoLite2 City

Sign up at <https://www.maxmind.com/en/geolite2/signup>, create a licence key,
and download `GeoLite2-City.mmdb` — by hand, or with MaxMind's
[`geoipupdate`](https://github.com/maxmind/geoipupdate) tool, which also keeps
it current. Point the VTC at the `.mmdb` file exactly as below. GeoLite2's
EULA has its own attribution and data-retention terms; read them before use.

## Configuring the VTC

In `config.toml`:

```toml
[geoip]
database = "/var/lib/vtc/geoip/dbip-city-lite.mmdb"
```

or in the environment, which overrides the file (an empty value turns it
off):

```sh
VTC_GEOIP_DATABASE=/var/lib/vtc/geoip/dbip-city-lite.mmdb
```

The file must be readable by the user the VTC runs as. At startup the log
says `GeoIP database loaded` with the database type and build time. If the
file is missing or is not a valid `.mmdb`, the VTC logs a **warning** and
starts anyway, with every location `unknown`: a location is advisory, and
sign-in works without it. Leaving `[geoip]` out keeps today's behaviour.

The VTC reads the whole file into memory (about the size of the unpacked
file), and briefly holds two copies while a new version loads.

## Keeping it current

The VTC checks the file's modification time and size once a minute and
re-reads it when either changes, so a refreshed database is picked up
**without a restart**. If the new file cannot be read — a half-finished
download, say — the VTC warns and keeps using the version it already has.

Replace the file atomically: write the new one beside it and `mv` it into
place, so the VTC never reads a partial file. A monthly cron job for DB-IP
(the file for a month appears on its first days; this runs on the 3rd):

```sh
# /etc/cron.d/vtc-geoip
15 4 3 * * vtc /usr/local/bin/vtc-geoip-update
```

```sh
#!/bin/sh
# /usr/local/bin/vtc-geoip-update — fetch this month's DB-IP City Lite.
set -eu
dir=/var/lib/vtc/geoip
tmp=$(mktemp "$dir/.dbip.XXXXXX")
trap 'rm -f "$tmp" "$tmp.gz"' EXIT
curl -fsSLo "$tmp.gz" \
  "https://download.db-ip.com/free/dbip-city-lite-$(date -u +%Y-%m).mmdb.gz"
gunzip -c "$tmp.gz" > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$dir/dbip-city-lite.mmdb"
```

In Kubernetes, the same script fits a `CronJob` writing to a volume the VTC
mounts read-only; the VTC picks the new file up within a minute of the `mv`.
