# SpireUEM device posture check for authentik.
#
# Paste this whole file into an authentik "Expression Policy" (Customization > Policies >
# Create > Expression Policy). authentik wraps it in a function, which is why it uses `return`.
# See docs/ACCESS_AUTHENTIK.md for setup, binding and pitfalls.
#
# The policy asks SpireUEM whether the device behind the login is COMPLIANT:
#   GET <SPIRE_URL>/api/admin/v1/posture/lookup?ip=<client ip>   (and/or ?user=<username>)
# using a SpireUEM service account that holds ONLY the posture:read scope.
#
# It fails closed. Anything other than a clean HTTP 200 whose body says allowed=true and
# state=COMPLIANT denies: timeout, connection error, HTTP error, redirect, malformed JSON,
# unknown device, ambiguous identity, stale verdict, missing token, missing client address.
#
# The token is read from the environment of the authentik server and worker containers
# (SPIRE_POSTURE_TOKEN) at evaluation time, so it is never stored in the policy body, the
# database or a blueprint export.

import os

# ---- configuration ----------------------------------------------------------------------
SPIRE_URL = "https://spire.example.internal"  # SpireUEM base URL, no trailing slash
# "ip":          the device is the one at the client address authentik sees (weak, see docs)
# "user":        the user's own device (last active desktop user = the login name; weak)
# "ip_and_user": both must resolve to the SAME compliant device (strongest of the three)
IDENTITY = "ip"
TOKEN_ENV = "SPIRE_POSTURE_TOKEN"
TIMEOUT = (2, 4)  # connect, read seconds. A slow SpireUEM denies logins; keep it short.
DENY_MESSAGE = "Access denied: this device does not meet the security requirements."
# -----------------------------------------------------------------------------------------


def deny(why):
    ak_logger.warning("spire posture: deny", reason=why)
    ak_message(DENY_MESSAGE)
    return False


def lookup(param, value, token):
    resp = requests.get(
        SPIRE_URL.rstrip("/") + "/api/admin/v1/posture/lookup",
        params={param: value},
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    if resp.status_code != 200:
        raise ValueError("SpireUEM answered HTTP %s" % resp.status_code)
    data = resp.json().get("data")
    if not isinstance(data, dict):
        raise ValueError("unexpected response shape")
    return data


token = os.environ.get(TOKEN_ENV, "")
if not token:
    return deny("no connector token in the environment (%s)" % TOKEN_ENV)
if IDENTITY not in ("ip", "user", "ip_and_user"):
    return deny("IDENTITY must be ip, user or ip_and_user")

queries = []
if IDENTITY in ("ip", "ip_and_user"):
    client_ip = str(ak_client_ip) if ak_client_ip else ""
    if not client_ip:
        return deny("authentik did not determine a client address")
    queries.append(("ip", client_ip))
if IDENTITY in ("user", "ip_and_user"):
    # Inside an authentication flow request.user may still be anonymous; the user being
    # logged in is context["pending_user"].
    user = request.context.get("pending_user") or request.user
    username = getattr(user, "username", "") or ""
    if not username or username == "AnonymousUser" or getattr(user, "is_anonymous", False):
        return deny("no user to look up yet")
    queries.append(("user", username))

device_ids = set()
for param, value in queries:
    try:
        data = lookup(param, value, token)
    except Exception as exc:  # timeout, connection refused, TLS, HTTP error, bad JSON
        return deny("lookup by %s failed: %s" % (param, exc))
    if data.get("allowed") is not True or data.get("state") != "COMPLIANT":
        return deny("lookup by %s: state=%s reasons=%s" % (param, data.get("state"), data.get("reasons")))
    device_ids.add(data.get("device_id"))

if len(device_ids) != 1 or None in device_ids:
    return deny("the address and the user resolve to different devices")
ak_logger.debug("spire posture: allow", device_id=next(iter(device_ids)))
return True
