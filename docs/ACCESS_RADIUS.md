# RADIUS / NAC connector (802.1X, MAC bypass, VPN)

SpireUEM is **not** a RADIUS server. FreeRADIUS (which also fronts switches, access points,
strongSwan and OpenVPN) asks SpireUEM for an access decision over HTTPS using its `rlm_rest`
module. SpireUEM answers from the device's single posture verdict (`device_posture`) and, when
that verdict later changes, pushes a RFC 5176 Disconnect-Request to the NAS so the device has to
authenticate again.

```
 supplicant ──802.1X/MAB──> switch / AP / VPN gateway (NAS)
                                │ Access-Request
                                ▼
                           FreeRADIUS ──rlm_rest, HTTPS, Bearer posture:read──> SpireUEM
                                ▲                                                  │
                                │ Access-Accept (+VLAN) / Access-Reject            │ posture changes
 NAS <──── Disconnect-Request (RFC 5176, UDP 3799, signed with the NAS secret) ────┘
```

Tested against FreeRADIUS 3.2.7 (`scripts/test_radius.sh`, see [Testing](#testing)).

## 1. What SpireUEM decides

| Posture (effective) | Result |
|---|---|
| COMPLIANT | Accept; VLAN attributes if a compliant VLAN is set |
| QUARANTINED | Accept into the quarantine VLAN if one is set, otherwise reject |
| NONCOMPLIANT | Accept into the remediation VLAN if one is set, otherwise reject |
| UNKNOWN, no verdict, verdict older than `valid_until` | Reject, unless the guest VLAN is explicitly enabled |
| device not found, or outside the caller's tag scope | Reject, unless the guest VLAN is explicitly enabled |
| ambiguous identity (MAC shared by two devices), malformed request, database error | **Always reject** (the guest VLAN never applies) |
| MAC identity while "accept MAC identity" is off (default) | **Always reject** |
| certificate presented but unknown, revoked or expired | **Always reject** (never falls back to the MAC) |

VLAN attributes are RFC 3580: `Tunnel-Type:0 = VLAN`, `Tunnel-Medium-Type:0 = IEEE-802`,
`Tunnel-Private-Group-Id:0 = "<vlan>"`. VLAN ids are digits 1-4094; anything else is refused when
the settings are saved.

Configure this on **Admin → RADIUS / NAC** (`/admin/radius`). SUPER_ADMIN and SECURITY_ADMIN
edit, everyone else reads. A tag-scoped SECURITY_ADMIN can read but not edit, because the mapping
is global. Every change is audited (`RADIUS_SETTINGS_UPDATE`, plus `RADIUS_GUEST_VLAN_CHANGE` and
`RADIUS_WEAK_IDENTITY_CHANGE` for the two risky switches, `RADIUS_NAS_*` for NAS clients).

## 2. Identity: what the decision rests on

| Identity | Source | Strength |
|---|---|---|
| Device-CA **network** certificate serial | `TLS-Client-Cert-Serial` (EAP-TLS) | **strong** |
| Certificate fingerprint | `TLS-Client-Cert-Fingerprint` if you compute and send one | strong |
| MAC address | `Calling-Station-Id` (MAC authentication bypass) | **weak**, off by default |

Responses that resolved a device by MAC carry `control:Tmp-String-1 = weak` and the HTTP header
`X-Spire-Identity-Strength: weak` (certificate answers say `strong`).

What a MAC proves: nothing. Any host on the same switch port or Wi-Fi network can copy a known MAC
address; MAC bypass therefore grants whatever the compliant (or remediation) VLAN grants to anyone
who has seen a compliant device's MAC. Use it only for devices that cannot do 802.1X, keep the
compliant VLAN of MAB devices low-privilege, and prefer EAP-TLS. The "accept MAC identity" switch
is off until an administrator turns it on, and turning it on is audited.

Note for 802.1X without a certificate (PEAP): FreeRADIUS still sends the supplicant's
`Calling-Station-Id`, so such requests are judged as weak MAC identities and rejected while that
switch is off.

**Certificate identity comes from the device's network certificate.** A `NETWORK_PROFILE` for
EAP-TLS can use `client_cert_source: device`. The agent then makes its own key (`network.key`,
root-only, never sent anywhere), asks SpireUEM for a certificate for it, and NetworkManager
presents that certificate. The certificate is signed by the SpireUEM device CA and names exactly
one device, so the serial FreeRADIUS reports maps to one device. See section 4a and
`docs/ADMIN_RUNBOOK.md` section 8.1.

The device CA signs three kinds of certificate per device: **agent** (the agent's own mTLS
identity), **network** (this connector) and **browser** (the forward-auth connector). FreeRADIUS
cannot tell them apart, because they chain to the same CA. SpireUEM can: this endpoint accepts a
serial only if it belongs to a **network** certificate. The agent and browser certificates of the
same device are refused even though their TLS handshake succeeds. A pasted per-policy certificate
(`client_cert_source` empty or `inline`) is not a device-CA certificate and identifies a policy,
not a device; it does not give strong identity here.

## 3. Credential and request format

Create a **service account** (Admin → API Access) with role AUDITOR and only the `posture:read`
scope. A tag-scoped service account sees only devices inside its tags: a device outside the scope
gets exactly the same answer as a device that does not exist (no existence oracle). Ambiguity is
judged before scoping, so a duplicate hidden by the scope still makes the match ambiguous.

`POST /api/admin/v1/access/radius/authorize` with `Authorization: Bearer spire_sa_...`.
The body is what `rlm_rest` sends with `body = 'json'` in FreeRADIUS 3.2, attributes as
`{"Name":{"type":"string","value":["x"]}}`. Read: `User-Name`, `Calling-Station-Id`,
`NAS-IP-Address` (or `NAS-IPv6-Address`), `NAS-Identifier`, `Acct-Session-Id`,
`TLS-Client-Cert-Serial` (hex, converted to the decimal serial SpireUEM stores),
`TLS-Client-Cert-Fingerprint`. An identity attribute with two different values is rejected.

| HTTP | Meaning | rlm_rest return code |
|---|---|---|
| 200 + marker | accept | ok / updated |
| 403 `{"decision":"reject"}` | reject; the body never says why (reasons are in the server log) | userlock |
| 401 | bad or missing credential | reject |
| 429 | too many failed authentications from the caller | invalid |
| 5xx | internal or database error | fail |

An accept body looks like:

```json
{"control:Tmp-String-0":"spire-accept","control:Tmp-String-1":"weak",
 "reply:Tunnel-Type:0":"VLAN","reply:Tunnel-Medium-Type:0":"IEEE-802","reply:Tunnel-Private-Group-Id:0":"10"}
```

Decisions are never cached or replayed (the endpoint does not take an `Idempotency-Key`).

## 4. FreeRADIUS setup (3.2)

Files are in `contrib/freeradius/`:

| File | Install as |
|---|---|
| `mods-available/spire` | `/etc/freeradius/mods-available/spire`, symlink into `mods-enabled/` |
| `mods-available/spire_eap_tls` | the `eap` module for EAP-TLS with the device CA (section 4a) |
| `policy.d/spire_nac` | `/etc/freeradius/policy.d/spire_nac` |
| `spire_token.conf.example` | `/etc/freeradius/spire_token.conf` (mode 0640, `root:freerad`) |
| `sites-available/spire-nac` | a complete example virtual server; copy its blocks into yours |

1. Put `$INCLUDE /etc/freeradius/spire_token.conf` at the top of `radiusd.conf` and the service
   account token into that file. The token is not written into the module or site files.
2. Edit the two `uri` lines of `mods-available/spire` to your SpireUEM server. Use **https** with a
   certificate FreeRADIUS verifies (`check_cert`, `check_cert_cn` stay `yes`; add `ca_file` for a
   private CA). SpireUEM refuses plain HTTP on reachable addresses itself.
3. Call `spire_nac_check` from your virtual server:
   * **MAC bypass**: in `authorize`, for requests with a MAC-shaped `User-Name` and no EAP:
     `spire_nac_check` and then `update control { &Auth-Type := Accept }` (Block 1 of the site).
   * **EAP-TLS**: in `post-auth`, after the handshake, copy the serial out of session-state into
     the request and call the policy (Block 2). The certificate is verified by the `eap` module
     against its `ca_file`; set that to the SpireUEM device CA only (section 4a).
4. Add the NAS to FreeRADIUS `clients.conf` as usual, with `require_message_authenticator = yes`.

### 4a. EAP-TLS with device certificates

1. **Trust the device CA, and only it, for client certificates.** The CA certificate is the
   `device_ca_certificate_pem` every issue response carries, and the file the server loads from
   `SPIRE_DEVICE_CA_CERT_FILE`. Save it as `/etc/freeradius/certs/device-ca.pem`. Install
   `mods-available/spire_eap_tls` as the `eap` module (or merge its `tls-config` block): it
   enables EAP-TLS only and sets `ca_file` to that file. Do not add your corporate CA to
   `ca_file`: every certificate it signed would pass the handshake and then be refused by
   SpireUEM as unknown, which is safe but noisy.
2. **Give FreeRADIUS its own server certificate** (`server.pem`, `server.key`), signed by a RADIUS
   server CA of yours, not by the device CA. Put that server CA in the `ca_cert` field of the
   `NETWORK_PROFILE` so the supplicant checks it.
3. **Pass the serial to SpireUEM.** The site's `post-auth` block already does:
   `&TLS-Client-Cert-Serial := &session-state:TLS-Client-Cert-Serial`, then `spire_nac_check`. The
   REST call sends it as `TLS-Client-Cert-Serial`; SpireUEM converts the hex serial to decimal and
   looks it up among **network** certificates only.
4. **Revocation.** The device CA publishes no CRL (`check_crl = no`). A revoked, expired or
   unknown certificate can still finish the TLS handshake; SpireUEM rejects it right after, on
   every authentication. Revoke a device and all its certificates stop working at the next
   authentication (existing sessions end through Disconnect, section 5).
5. **What happens to each certificate** (all verified in section 7):

   | Presented certificate | Result |
   |---|---|
   | network certificate, device compliant | accept, compliant VLAN |
   | network certificate, device non-compliant or quarantined | remediation or quarantine VLAN, or reject when none is set |
   | network certificate, revoked or expired | reject |
   | agent or browser certificate of the same device | reject |
   | certificate from any other CA | reject in the TLS handshake |

The device's network certificate lasts as long as agent certificates (30 days by default). The
agent renews it at about two thirds of its life with a new key, and keeps the old pair if
renewal fails.

### Fail-closed behaviour

`spire_nac_check` accepts only when the answer carried `control:Tmp-String-0 = "spire-accept"`.
Any other outcome rejects: timeout, connection refused, DNS failure, TLS failure, 401/403/404/5xx,
unparseable JSON, a 200 without the marker. The marker is cleared before the call so a stale value
cannot satisfy it, and the test is a positive match so an absent attribute rejects (never
"noop then accept"). The module has no `connect_uri`, so FreeRADIUS starts and rejects while
SpireUEM is down instead of refusing to start. `do_xlat = no` stops response values from being
evaluated as expressions. Verified by `scripts/test_radius.sh` (SpireUEM stopped → Access-Reject,
restarted → accept).

Rejecting everything while SpireUEM is unreachable is deliberate. If you cannot accept that
outage mode, run SpireUEM highly available rather than softening the policy.

## 5. NAS clients and Disconnect (CoA)

On **Admin → RADIUS / NAC → NAS clients** add each switch, access point or VPN gateway SpireUEM may
disconnect sessions on: name, **IP address** (as it appears in `NAS-IP-Address`; no host names),
CoA port (default 3799) and the **shared secret** the NAS uses for dynamic authorization.

* The secret is sealed with the server KEK (same envelope as webhook and alert secrets), shown
  only if SpireUEM generated it (once, on creation), never returned by any page or API, and never
  written to the audit log. To change it, enter a new one.
* Loopback, link-local (including the cloud-metadata address), multicast and unspecified addresses
  are refused at save time and again at connect time. Private ranges are allowed: a NAS lives on a
  management network. SpireUEM connects only to addresses listed here.
* The NAS must allow SpireUEM's source address for dynamic authorization (Cisco `aaa server radius
  dynamic-author`, Aruba/Juniper/Mikrotik equivalents, strongSwan/OpenVPN: see section 6).

How it works:

1. Each accepted authorize call from a **registered, enabled** NAS address records a session
   (device, NAS, `Calling-Station-Id` and `User-Name` exactly as the NAS sent them, the posture state
   it was admitted under, 12 h expiry). Requests from unregistered NAS addresses record nothing.
2. A loop on every SpireUEM server reads `device_posture.state_changed_at` past a persisted cursor
   (re-scanning a 30 s window, since a verdict can commit slightly late) and queues one
   Disconnect-Request for each live session admitted under a different state.
3. The queue is claimed with `FOR UPDATE SKIP LOCKED`; a unique key on (device, NAS, session,
   `state_changed_at`) and one advisory lock on the scan mean two servers send each disconnect once.
4. A Disconnect-Request carries `User-Name`, `Calling-Station-Id`, `NAS-IP-Address`,
   `NAS-Identifier`, `Acct-Session-Id` (if the NAS sent one), `Event-Timestamp` and a
   `Message-Authenticator`, and is signed per RFC 5176 §2.3. A response is accepted only with a valid
   Response Authenticator. One claim sends the identical packet up to 3 times (3 s apart); a
   timeout is retried on a later claim (30 s, 60 s), at most 3 claims, then `FAILED`. A NAK is final.
   "Session context not found" (error cause 503) counts as success: the session is already gone.
5. The delivery log is on the same page. The loop only reads `device_posture` and writes its own
   tables, so it cannot slow posture evaluation or check-in.

A reconnecting device is judged again by `authorize`, so it lands in the VLAN that matches its new
verdict.

## 6. VPN concentrators

Both strongSwan and OpenVPN use the same FreeRADIUS server and the same two sections.

**strongSwan `eap-radius`** (IKEv2 EAP-TLS or EAP-MSCHAPv2 with RADIUS accounting):

```
charon { plugins { eap-radius {
    servers { spire-fr { address = <freeradius ip>  secret = <client secret>  auth_port = 1812  acct_port = 1813 } }
    # strongSwan accepts Disconnect-Requests from the RADIUS servers' addresses
    dae { enable = yes  listen = 0.0.0.0  port = 3799  secret = <NAS CoA secret> }
} } }
```

Authenticate with EAP-TLS so FreeRADIUS sees the client certificate and the post-auth block applies;
register the strongSwan gateway as a NAS client with `dae.secret` as the shared secret. With
EAP-MSCHAPv2 there is no certificate, the request carries no device-CA identity, and it is rejected
unless MAC identity is accepted (and a VPN client's `Calling-Station-Id` is its IP address, not a
MAC, so that does not work either). VPN posture therefore needs EAP-TLS with device certificates.

**OpenVPN `radiusplugin`**: configure the plugin against FreeRADIUS and run it with
certificate verification (`tls-verify`/`client-cert-not-required` off) so FreeRADIUS receives the
certificate serial. The stock plugin does not implement dynamic authorization; without it SpireUEM
cannot disconnect an OpenVPN session on a posture change and the new verdict applies at the next
authentication. Shorten the session lifetime (`reneg-sec`) if that matters to you.

On an overlay such as WireGuard or NetBird the source IP of a peer is bound to its key, which makes
IP-based identity much stronger there than on a LAN. This connector does not use IP identity.

## 7. Testing

`scripts/test_radius.sh` builds the server, starts FreeRADIUS 3.2.7 in Docker (host network,
loopback and the Docker bridge address only) and a throwaway database, and with `radclient` proves:
MAB accept with VLAN attributes; non-compliant → remediation VLAN or reject; quarantine; stale
verdict, unknown MAC, disabled MAC identity, mismatching `User-Name`: reject; SpireUEM down: reject.
FreeRADIUS then acts as the NAS: a posture change makes SpireUEM send a Disconnect-Request that
FreeRADIUS validates (authenticator and `Message-Authenticator`), exactly one per change, and a wrong
shared secret is never acknowledged.

The same script then runs EAP-TLS with a real supplicant. It starts a second `spire-server`
that terminates TLS (the issue endpoint needs the agent certificate in the handshake), enrolls
devices and obtains their network certificates through the real `POST /api/v1/desktop/cert/issue`
(`test/eaptls_helper`, which stands in for the agent's request), and authenticates with
`eapol_test` (Debian package `eapoltest`, built into a small local image) against FreeRADIUS using
`contrib/freeradius/mods-available/spire_eap_tls`. It shows the results in the table in section 4a:
compliant device accepted with the compliant VLAN, quarantined device in the quarantine VLAN or
rejected, remediation VLAN, revoked network certificate rejected, the device's agent certificate
rejected by SpireUEM (the log shows `unknown_certificate`, so the TLS layer let it through), and a
certificate from an untrusted CA rejected in the handshake. The test needs `openssl`.

## 8. Limits

* A session whose verdict merely expires (`valid_until` passes without a state change) is not
  disconnected; the next authentication rejects it. Connected devices that go offline keep their
  port until the NAS ends the session.
* Only Disconnect is sent. A VLAN change by CoA-Request is not implemented.
* Sessions are learned from authorize calls. Accounting is not used, so `Acct-Session-Id` is stored
  only if the NAS includes it in the Access-Request.
* Guest-VLAN devices that SpireUEM does not know have no session record and are not disconnected
  when they later enrol.
* Message-Authenticator in Disconnect-Requests uses the RFC 5176 zero-authenticator form; a NAS that
  computes it differently will drop the packet. FreeRADIUS accepts it; check your NAS vendor.
