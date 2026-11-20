# Device posture for reverse proxies (forward-auth)

SpireUEM keeps one access verdict per device (`COMPLIANT`, `NONCOMPLIANT`, `QUARANTINED`, `UNKNOWN`).
A reverse proxy can ask SpireUEM for that verdict before it lets a request through to an application:

```
browser --> proxy --(forward-auth, GET)--> SpireUEM  /api/admin/v1/access/forward-auth
               |                                 |
               | 200 = allow, 403 = deny         +-- identity -> one device -> effective posture
               v
          application
```

SpireUEM does not become an identity proxy. It answers one question, "is the device behind this request
compliant right now", and the proxy enforces the answer. The proxy's own SSO (Pangolin, Authentik, oauth2-proxy)
stays in front and decides who the user is. For Authentik at login time see `docs/ACCESS_AUTHENTIK.md`.

## The endpoint

`GET /api/admin/v1/access/forward-auth`

| Status | Meaning |
|---|---|
| `200` | Allow. Headers `X-Spire-Device-Id`, `X-Spire-Posture: COMPLIANT`, `X-Spire-Identity-Strength: strong\|weak` may be passed to the application. |
| `403` | Deny. One generic body for every reason (unknown device, noncompliant, stale, ambiguous, untrusted proxy, bad certificate, weak identity disabled, out of tag scope). The reason is in the SpireUEM log, not in the response. |
| `401` | The proxy's own credential is missing or wrong. |
| `503` | SpireUEM could not check (database or settings error). Treated by every proxy as a refusal. |

Fail closed: the only path to `200` is a service account with `posture:read`, a TCP peer inside the trusted-proxy
ranges, a client identity that parses and resolves to exactly one APPROVED device inside the account's tag scope,
and an effective state of `COMPLIANT`. A missing verdict and a verdict past `valid_until` both read `UNKNOWN` and deny.

## One-time setup

1. **Create the connector account** (Settings > Service accounts): role cap `AUDITOR`, scope `posture:read` and
   nothing else. Add allowed tags if the proxy only protects some devices; a device outside the tags is
   indistinguishable from an unknown one. Copy the token once.
2. **Trusted proxies** (Admin > Access Proxy, `SUPER_ADMIN` or an unscoped `SECURITY_ADMIN`): list **only the
   addresses of the proxies that call SpireUEM**, for example `10.0.0.5`. Do not list a client network, a whole
   LAN, `0.0.0.0/0` (refused) or the network your users sit on. Anything inside this list can tell SpireUEM who the
   client is, so a too-wide range lets those hosts claim any device's address. Empty (the default) means
   forward-auth denies every request.
3. **Pick the identity** (below) and the header that carries it.
4. Configure the proxy. The per-proxy examples below each solve the same problem: the proxy's token must reach
   SpireUEM and **must not** reach the protected application.

Every change on the page is audited (`ACCESS_PROXY_SETTINGS_CHANGE`, with before and after values). Tag-scoped
administrators cannot change it: the settings are fleet-wide.

## How the client is identified

| Identity | Strength | When SpireUEM uses it |
|---|---|---|
| Client certificate issued by the SpireUEM device CA | strong | A certificate header is configured on the Access Proxy page and the request carries it. |
| Source IP address | weak | No certificate on the request, and "Accept a source IP address as the device identity" is on. |

### What the proxy must do (read this)

SpireUEM believes the identity headers only because the proxy wrote them. The proxy therefore **must overwrite or
strip every identity header a client could send itself**:

* **`X-Forwarded-For` / `X-Real-IP`**: the proxy must replace the client's value with the address it actually saw
  (nginx `proxy_set_header X-Forwarded-For $remote_addr;`, Traefik's default `trustForwardHeader: false`, Caddy's
  default). SpireUEM reads **one** header, the one chosen on the Access Proxy page, and for `X-Forwarded-For` it
  walks from the right and skips addresses that are themselves trusted proxies, so entries a client prepended on
  the left are never used. If the proxy appends to a client-supplied list instead (Traefik `trustForwardHeader: true`), the
  rightmost untrusted entry is the address the proxy saw, so a forged leftmost entry is still ignored; do not rely on
  that for an edge proxy, and keep the default.
* **Client certificate header**: the proxy must set it on every request and **delete it when the client presented no
  certificate**. A device certificate is not a secret (it is sent in the clear in a TLS handshake and shown in
  inventories), so a client that can write the header itself can replay someone else's certificate. SpireUEM
  only honours the single header you name, only from a trusted proxy, and verifies the chain to the device CA, the
  client-auth key usage, the validity period, that the serial is registered and not revoked, and that the device id
  in the certificate matches the registered device. It cannot verify that the client holds the private key; only a
  proxy that finished the TLS handshake can vouch for that.
* **The connector token**: see per-proxy notes. It must never be sent to the application.

A request whose TCP peer is **not** in the trusted-proxy list is refused before any header is read, so a client that
reaches SpireUEM directly cannot supply an address or certificate. SpireUEM also records the real TCP peer before
`SPIRE_TRUST_PROXY` rewrites `RemoteAddr` from `X-Real-IP`, so a client cannot pose as the proxy through that header.

### What weak (IP) identity means

The IP address is the address the device last checked in from (`last_seen_ip`). It is a hint, not proof:

* On a LAN another machine can take the address (static address, ARP spoofing, a DHCP lease handed on) and inherit a
  compliant verdict until the real device checks in again from elsewhere.
* Several devices behind one NAT address are **ambiguous** and always deny.
* Anyone able to send traffic from the address, or to make the proxy report it, is that device for SpireUEM.

On a WireGuard or NetBird overlay the source address is bound to the peer's key by the tunnel (a peer cannot send
packets from another peer's overlay address), so IP identity is much stronger there. That is the practical setup
today: **protect applications over the overlay and turn weak identity on only for that path.**

Browsers do not hold the SpireUEM device certificate today (it is `spired`'s mTLS key). Certificate-based
forward-auth therefore needs browser certificate profiles (roadmap item 2), which are not built. The certificate
path is implemented and tested, but there is nothing in the product yet that puts the certificate into a browser.

## Keeping the connector token away from the application

The token only reads posture, but it also enumerates which addresses map to which compliance state, so do not hand
it to the applications you protect.

| Proxy | How the credential is attached | Reaches the application? |
|---|---|---|
| nginx `auth_request` | `proxy_set_header Authorization "Bearer ..."` inside the internal auth location only. | No. The main location never sees it, and the application's own `Authorization` header is untouched. |
| Caddy `forward_auth` | `header_up Authorization "Bearer ..."` inside the `forward_auth` block. | No, same reasons. |
| Traefik `forwardAuth` | Cannot add a header to the auth request alone: it forwards the original request's headers. Add `X-Spire-Connector-Token` with a headers middleware **before** `forwardAuth`, and remove it with a second headers middleware **after**. | Not if the strip middleware is in the chain. Order matters. |

SpireUEM accepts the token as `Authorization: Bearer` or, only on this endpoint, as `X-Spire-Connector-Token`. The
second form exists for Traefik so the application's own `Authorization` header (user session, API key) is not
overwritten. When both are present the dedicated header wins and replaces `Authorization`.

Options considered for Traefik and rejected:

* **Token in the URL path or query**: ends up in proxy and server logs, and is a new credential shape.
* **mTLS from the proxy to SpireUEM**: needs a second credential type (a connector CA) that SpireUEM does not have.
* **`Authorization` header via a headers middleware, then strip**: works, but clobbers the client's own
  `Authorization` for applications that use it. The dedicated header avoids that.
* **Not stripping and relying on the application to ignore it**: the token is still disclosed to the application and
  its logs.

`scripts/test_access_proxy.sh` checks this on real Traefik, nginx and Caddy, including a control route without the
strip middleware that proves the leak check can fail.

## Traefik (v3), including Pangolin

Dynamic configuration (file provider). Replace the address and token.

```yaml
http:
  middlewares:
    spire-add-token:
      headers:
        customRequestHeaders:
          X-Spire-Connector-Token: "spire_sa_..."      # keep this file mode 0600
    spire-posture:
      forwardAuth:
        address: "https://spire.internal.example/api/admin/v1/access/forward-auth"
        # trustForwardHeader stays false (the default): Traefik then REPLACES X-Forwarded-For with the
        # address it saw, so a client cannot forge it.
        authResponseHeaders: [X-Spire-Device-Id, X-Spire-Posture, X-Spire-Identity-Strength]
    spire-strip-token:
      headers:
        customRequestHeaders:
          X-Spire-Connector-Token: ""                  # empty value removes the header
    spire-device-posture:
      chain:
        middlewares: [spire-add-token, spire-posture, spire-strip-token]   # this order
  routers:
    app:
      rule: "Host(`app.example`)"
      entryPoints: [websecure]
      middlewares: [spire-device-posture]
      service: app
```

Set the Access Proxy page to: trusted proxies = Traefik's address as SpireUEM sees it, header = `X-Forwarded-For`,
weak identity on if you identify by address. For certificates also set `passTLSClientCert` (`pem: true`) with
`tls.clientAuth` on the entry point, name the header `X-Forwarded-Tls-Client-Cert`, and make sure no client can set
it on routes without client-certificate auth.

**Pangolin.** Pangolin's own SSO gate stays in front and answers who the user is; this adds which device. Pangolin
runs Traefik, so add the three middlewares to its dynamic configuration and reference the chain from the resource's
router. Pangolin regenerates its managed Traefik configuration, so put the middlewares in a separate file-provider
file that Pangolin does not overwrite and verify that it lists the middleware on the router it generates. Traefik
sits behind Pangolin's own tunnel for remote sites, so the address SpireUEM sees is the tunnel's, not the user's;
weak identity is only meaningful where Traefik sees the real client address.

## nginx (`auth_request`)

```nginx
location / {
    auth_request /_spire_posture;
    auth_request_set $spire_dev $upstream_http_x_spire_device_id;
    auth_request_set $spire_pos $upstream_http_x_spire_posture;
    auth_request_set $spire_str $upstream_http_x_spire_identity_strength;
    proxy_set_header X-Spire-Device-Id         $spire_dev;   # overwrites anything the client sent
    proxy_set_header X-Spire-Posture           $spire_pos;
    proxy_set_header X-Spire-Identity-Strength $spire_str;
    proxy_pass http://app;
}
location = /_spire_posture {
    internal;
    proxy_pass https://spire.internal.example/api/admin/v1/access/forward-auth;
    proxy_method GET;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Authorization "Bearer spire_sa_...";    # only on the auth subrequest
    proxy_set_header X-Forwarded-For $remote_addr;           # overwrite, never append
    # with certificates:  proxy_set_header X-Ssl-Client-Cert $ssl_client_escaped_cert;
    #   (name that header on the Access Proxy page; it is set on every request, empty when no certificate)
}
```

The token is set only in the internal location, so the protected application never receives it and keeps the
client's own `Authorization` header.

## Caddy (`forward_auth`)

```caddy
app.example {
    forward_auth spire.internal.example:443 {
        uri /api/admin/v1/access/forward-auth
        header_up Authorization "Bearer spire_sa_..."   # applies to the auth request only
        copy_headers X-Spire-Device-Id X-Spire-Posture X-Spire-Identity-Strength
        transport http {
            tls
        }
    }
    reverse_proxy app:8080
}
```

Caddy's `reverse_proxy` sets `X-Forwarded-For` from the real connection unless you configure `trusted_proxies`; leave
that unset on an edge proxy. For certificates, add `header_up X-Client-Cert {http.request.tls.client.certificate_der_base64}`
inside `forward_auth` and name that header on the Access Proxy page.

## Testing and troubleshooting

`scripts/test_access_proxy.sh` starts Traefik, nginx and Caddy in Docker on 127.0.0.1 in front of an echo backend and
a SpireUEM built from your checkout, then proves: compliant allowed with headers, noncompliant / unknown / ambiguous
refused, token never reaches the application, spoofed `X-Forwarded-For` ignored, weak identity switch.

Every `403` has the same body. To see why, read the SpireUEM log line `[forward-auth] deny request_id=...: <reason>`
(the reasons never include tokens or certificates). Common ones: `request does not come from a trusted proxy`
(address list), `weak (IP) identity is disabled`, `ambiguous identity` (NAT), `device posture is UNKNOWN` (no
verdict yet or it expired).
