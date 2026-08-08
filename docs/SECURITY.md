# Credentials and sensitive artifacts

## Local `.env`

The account credentials and both supplied proxy profiles are stored in:

```text
/home/sdancer/ms/.env
```

Required permissions:

```sh
chmod 600 /home/sdancer/ms/.env
```

The variables are:

```text
MAPLE_ACCOUNT_EMAIL
MAPLE_ACCOUNT_PASSWORD
MAPLE_ACCOUNT_PROVIDER

MAPLE_TW_PROXY_SCHEME
MAPLE_TW_PROXY_HOST
MAPLE_TW_PROXY_PORT
MAPLE_TW_PROXY_USER
MAPLE_TW_PROXY_PASSWORD

MAPLE_HK_PROXY_SCHEME
MAPLE_HK_PROXY_HOST
MAPLE_HK_PROXY_PORT
MAPLE_HK_PROXY_USER
MAPLE_HK_PROXY_PASSWORD

MAPLE_PROXY_PROFILE
MAPLE_PROXY_HOST
MAPLE_PROXY_PORT
MAPLE_PROXY_USER
MAPLE_PROXY_PASSWORD
```

The generic `MAPLE_PROXY_*` values are the active/default profile consumed by
the transparent relay. The region-specific variables preserve both supplied
profiles.

Load the file without displaying it:

```sh
set -a
. /home/sdancer/ms/.env
set +a
```

Do not run `cat`, `env`, `set`, or `ps e` in logs/screenshares after loading
it. Do not pass passwords directly on a command line.

## Do not commit or share

- `.env` contains raw credentials and must never be committed.
- Protocol JSONL files may contain login tickets, session identifiers, or
  encrypted authentication payloads. Treat them as private even though proxy
  credentials are not written into them.
- Chromium's `/tmp/maple-proxied-login` profile contains authenticated browser
  state while it exists.
- Packet captures (`.pcap`), strace logs, Wine logs, and screenshots can reveal
  endpoints, tokens, account identifiers, or window content.

## File modes

The capture implementation creates directories as `0700` and transcripts as
`0600`. Keep `.env` at `0600`. If copying the lab to another machine, preserve
these permissions and use an encrypted transport/storage location.
