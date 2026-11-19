# Device posture in Authentik

`contrib/authentik/spire_posture_policy.py` is an Authentik **Expression Policy**. When a user logs in or opens an
application, it asks SpireUEM whether the device behind the request is `COMPLIANT` and denies if not. Reverse-proxy
forward-auth (Traefik, nginx, Caddy) is covered in `docs/ACCESS_PROXY.md`; use that when you want a check on every
request instead of at login.

## What it does

* Calls `GET /api/admin/v1/posture/lookup?ip=<client ip>` and/or `?user=<login name>` with a SpireUEM service
  account that holds only `posture:read`.
* Passes only when SpireUEM answers HTTP 200 with `allowed: true` **and** `state: COMPLIANT`.
* **Fails closed.** A timeout, connection error, TLS error, any other HTTP status, a redirect, malformed JSON, an
  unknown device, an ambiguous address, a stale verdict, a missing token or a missing client address all deny.
* On deny shows one generic message. SpireUEM's reasons and the token go to authentik's log at most (never the token).

`IDENTITY` in the file selects the lookup:

| `IDENTITY` | Looks up | Notes |
|---|---|---|
| `ip` (default) | the address authentik sees (`ak_client_ip`) | Weak identity, see below. |
| `user` | the device whose last active desktop user is the login name | Weak. It checks the user's own machine, not the machine making this request. |
| `ip_and_user` | both | Both must be compliant **and the same device**. The strongest combination available without certificates. |

## Setup

1. **SpireUEM**: create a service account with role cap `AUDITOR` and scope `posture:read` only. Add allowed tags if
   the application is only for some devices (devices outside the tags read as unknown, so they deny). Copy the token.
2. **Put the token in the environment of authentik's `server` and `worker`** as `SPIRE_POSTURE_TOKEN`, from a
   secret or env file, not in the policy:
   ```yaml
   services:
     server:
       environment:
         SPIRE_POSTURE_TOKEN: ${SPIRE_POSTURE_TOKEN}
     worker:
       environment:
         SPIRE_POSTURE_TOKEN: ${SPIRE_POSTURE_TOKEN}
   ```
   Authentik has no secret store that expression policies can read. Trade-off: the policy reads the variable when it
   runs, so the token never lands in the policy body, the database, a blueprint or an export. Anyone who can
   create or edit expression policies can run Python in the authentik process and read the variable; authentik
   itself treats that permission as highly privileged, so grant it sparingly. The alternative, a literal in the
   policy body, is readable by everyone who can read the policy and by every export, so it is not recommended.
3. **Create the policy**: Customization > Policies > Create > Expression Policy. Paste the file. Set
   `SPIRE_URL` (`https://spire.example`, no trailing slash) and `IDENTITY`. The connection and read timeouts are
   `TIMEOUT = (2, 4)` seconds: a slow SpireUEM denies logins, so keep it short and SpireUEM close. Use https and,
   for a private CA, point `REQUESTS_CA_BUNDLE` at it in authentik's environment.
   Through the API:
   ```sh
   BODY=$(python3 - <<'PY'
   import json
   print(json.dumps({"name": "spire-device-posture", "execution_logging": True,
                     "expression": open("contrib/authentik/spire_posture_policy.py").read()}))
   PY
   )
   curl -s -X POST -H "Authorization: Bearer $AUTHENTIK_TOKEN" -H "Content-Type: application/json" \
        -d "$BODY" https://authentik.example/api/v3/policies/expression/
   ```
4. **Bind it** (below).
5. **Tell authentik who the client is.** `ak_client_ip` is the address authentik derived, and it honours
   `X-Forwarded-For` only from the networks in `AUTHENTIK_LISTEN__TRUSTED_PROXY_CIDRS`. Set that to your reverse
   proxy's address only. If it is too wide, a client can write its own `X-Forwarded-For` and pick the address that
   the policy looks up.

## Binding

* **To an application** (Applications > the app > Policy / Group / User Bindings): the user is refused access to
  that application. Bind the policy here for most uses.
* **To a flow or stage binding** (for example before the login stage): it runs during authentication. Inside an
  authentication flow `request.user` may still be anonymous; the policy uses `context["pending_user"]` for the `user`
  and `ip_and_user` modes, so the user lookup is correct there. Before the identification stage no user is known and
  `user` mode denies.

Pitfalls:

* A policy binding set to **Negate** inverts the result; an unbound policy does nothing.
* An application or binding whose **policy engine mode is "any"** and has no passing binding at all authorizes
  nobody (authentik denies when nothing passes). With mode "all", a single failing policy denies.
  If you combine this policy with a group check, use "all" so the posture check cannot be bypassed by the group.
* **Superusers are not exempt** unless you bind it that way; test with an ordinary user and with the break-glass
  account you will use if SpireUEM is down. When SpireUEM is unreachable every guarded login is refused, by design.
* "Failure result" on a binding applies when the policy raises. The policy catches its own errors and returns
  `False`, so an error never passes, but leave the binding's failure result on **Fail** anyway.
* Authentik caches policy results per user and application for a short time (check its policy cache settings for
  your version). A device that becomes noncompliant keeps access until the cached result expires. Use forward-auth
  (`docs/ACCESS_PROXY.md`) when you need a per-request check.

## What identity strength you get

IP and user name are **weak** identities (SpireUEM labels them `identity_strength: "weak"`).

* Anyone who can send traffic from the address, or make a proxy report it, is that device for the check. On a LAN
  an address can be reused or spoofed.
* Several devices behind one address (NAT) are ambiguous and deny.
* On a WireGuard or NetBird overlay the source address is bound to the peer key, so address identity is much
  stronger there. Prefer protecting applications over the overlay.
* `user` mode proves nothing about the machine in the browser: it reports the compliance of whichever device last had
  that user active. Prefer `ip_and_user` where both are available.

## Tests

* `python3 contrib/authentik/test_spire_posture_policy.py` runs the real policy file against a mock SpireUEM, wrapped the
  way authentik wraps expression policies. It covers allow, every deny class, redirects, timeouts, missing token,
  missing address, URL-encoding of the user name and the same-device rule.
* `scripts/test_access_authentik.sh` starts authentik (server, worker, Postgres) and a SpireUEM in local Docker, creates
  the policy through authentik's API and evaluates it with authentik's policy test endpoint. It needs the image
  `ghcr.io/goauthentik/server` and a few minutes for authentik's first start.
