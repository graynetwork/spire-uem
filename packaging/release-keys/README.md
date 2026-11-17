# Pinned release-signing trust anchors

Every `*.pub` file in this directory is installed into the agent package at
`/usr/share/spire/release-keys/<key_id>.pub` and becomes a trust anchor the agent pins for
independent update-manifest verification. The agent NEVER fetches these keys from the control
plane, so a compromised server cannot add a key it controls.

The `.pub` files are Ed25519 public keys in PKIX PEM. Their file name is the `key_id` (the
first 16 hex chars of the SHA-256 of the raw public key), which is how the agent selects the
right key for a manifest.

## Rotation

Multiple keys may live here at once. To rotate:

1. `spire-release keygen -out <secure-dir>` on an offline/HSM host — this prints a new
   `key_id` and writes `<key_id>.pub`.
2. Add the new `<key_id>.pub` here and ship a new agent package, so fielded agents trust BOTH
   the old and new key.
3. Start signing releases with the new key.
4. Once every agent runs a package that trusts the new key, remove the old `.pub` and ship
   again.

## The sample key in this repo

`539098ba5068b74d.pub` is a SAMPLE key whose private half is NOT in this repository and is
NOT a production key. It exists only so the packaged layout and tests have a real anchor.
**Generate your own key pair for production and replace this file**; keep the private key off
the control plane (ideally offline or in an HSM-backed signer).
