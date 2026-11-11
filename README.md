# nak bunker for Umbrel

A self-hosted [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) remote signer
("bunker") for [Umbrel](https://umbrel.com), packaged from
[fiatjaf/nak](https://github.com/fiatjaf/nak).

Your Nostr key stays on your Umbrel, encrypted. Apps such as WordPress plugins, web clients or
bots ask the bunker to sign over Nostr relays and never see the key.

This is a thin port in the style of [hermes-agent-umbrel](https://github.com/getumbrel/hermes-agent-umbrel):

- **nak is unmodified.** The image downloads the official `nak` release binary for your
  architecture and checks it against the SHA-256 digest GitHub publishes for that release.
- **A small web shim** (one Python file, standard library only, `shim/nakbunker.py`) replaces
  the terminal. It runs `nak bunker --persist` in a pseudo-terminal and answers its password
  prompt from a web page behind Umbrel's login.

## What the web page does

- **Set up:** import an encrypted key (`ncryptsec1…`, checked against its password before
  saving), import an `nsec`/hex key (encrypted with NIP-49 before it touches disk), or generate
  a new key. nak is never started without an encrypted key, because it would otherwise fall
  back to a machine-default key.
- **Unlock** after every app or Umbrel restart. Optionally keep the bunker unlocked until the
  app restarts: the password then stays in memory, so if nak exits (for example when no relay
  is reachable at startup) the shim restarts and unlocks it unattended. nak already holds the
  decrypted key in memory while running, so this adds little exposure. A wrong password is
  never remembered or retried.
- **Status:** relay connection results, the log (keys, secrets and passwords masked), and the
  `bunker://` URI to connect a new app.
- **Relays:** edit the list (nak restarts). nak reconnects to dropped relays on its own.
- **Authorised apps:** list and remove.

There is no built-in monitoring or notification service. Use whatever you already have.

## Data

Everything lives in the app's data folder, in nak's own format:
`.config/nak/bunker/default` (JSON: encrypted key, relays, authorised clients, mode 600).
To move an existing `nak bunker --persist` setup, stop the app, copy your
`~/.config/nak/bunker/default` there, and start it. Clients you already authorised keep working.
The format is the same from nak v0.19 to v0.22.

To start over, stop the app and delete that file. This deletes your key from the app; keep a
backup of your `ncryptsec`/`nsec`.

## Security notes

- The web page is reachable only through Umbrel's app proxy (Umbrel login). State-changing
  requests also need a per-process CSRF token.
- Importing an `nsec` or generating a key passes the key and password to `nak key encrypt` as
  process arguments, inside this container only, for under a second.
- The `bunker://` URI shown on the page contains a single-use connection secret. Anyone with
  it can authorise one new client, so only paste it into apps you trust.

## Updating nak

Edit `NAK_VERSION` and the two `NAK_SHA256_*` values in the `Dockerfile` (use the digests shown
for `nak-nodb-<version>-linux-amd64` and `-arm64` on the GitHub release), then push a tag
`v<nak version>-<n>`. GitHub Actions builds and publishes
`ghcr.io/<owner>/nak-bunker-umbrel:<tag>` for amd64 and arm64 and prints the digest to pin in
the Umbrel app's `docker-compose.yml`.

## Tests

`tests/e2e_local.py` runs the shim with the real nak binary against public relays, using a
throwaway key, and a real NIP-46 client (connect, get_public_key, sign_event; nothing is
published). It covers setup validation, unlock, wrong passwords, unattended restart after nak
is killed, relay edits, client removal, and checks that no secret reaches the log.

```bash
# needs nostr-tools@2, ws@8 and @noble/hashes@1 in $PKG/node_modules
NAK_BIN=/path/to/nak PKG=/path/to/pkg python3 -I tests/e2e_local.py
```

## Licence

The shim and packaging are MIT. nak is released into the public domain (Unlicense) by its
authors; this project is not affiliated with them.
