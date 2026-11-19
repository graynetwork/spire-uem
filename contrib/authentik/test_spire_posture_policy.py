"""Unit tests for spire_posture_policy.py against a mock SpireUEM, in plain python3.

Run: python3 contrib/authentik/test_spire_posture_policy.py

authentik wraps an expression policy in `def handler(<context names>): <body>`, runs it with
helper functions as globals and `requests` as a Session. run_policy() reproduces that wrapping
so the real policy file is what gets tested.
"""
import json
import os
import re
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from textwrap import indent

import requests as requests_lib

POLICY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spire_posture_policy.py")
TOKEN = "spire_sa_0123456789abcdef_" + "a" * 64


class Mock(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.script = {}  # query-string -> (status, body, delay, headers)
        self.seen = []  # (path, query, authorization)
        super().__init__(("localhost", 0), self._handler())

    def _handler(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                path, _, query = self.path.partition("?")
                outer.seen.append((path, query, self.headers.get("Authorization")))
                status, body, delay, headers = outer.script.get(query, (404, b"{}", 0, {}))
                time.sleep(delay)
                if isinstance(body, (dict, list)):
                    body = json.dumps(body).encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        return H

    @property
    def url(self):
        return "http://localhost:%d" % self.server_address[1]


def data(allowed=True, state="COMPLIANT", device_id="dev-1", reasons=None):
    return {"data": {"allowed": allowed, "state": state, "device_id": device_id, "hostname": "h",
                     "identity_strength": "weak", "matched_by": "ip", "reasons": reasons or []}}


class Recorder:
    def __init__(self):
        self.messages, self.logs = [], []

    def message(self, m):
        self.messages.append(m)

    class Logger:
        def __init__(self, outer):
            self.outer = outer

        def warning(self, *a, **k):
            self.outer.logs.append(("warning", a, k))

        def debug(self, *a, **k):
            self.outer.logs.append(("debug", a, k))

        info = error = debug


class User:
    def __init__(self, username):
        self.username = username
        self.is_anonymous = False


def run_policy(url, ip="198.51.100.7", user=None, pending=None, identity="ip", token=TOKEN,
               timeout="(0.4, 0.4)", env_name="SPIRE_POSTURE_TOKEN"):
    src = open(POLICY).read()
    src = re.sub(r'^SPIRE_URL = ".*?"', 'SPIRE_URL = "%s"' % url, src, flags=re.M)
    src = re.sub(r'^IDENTITY = ".*"', 'IDENTITY = "%s"' % identity, src, flags=re.M)
    src = re.sub(r"^TIMEOUT = \(.*?\)", "TIMEOUT = %s" % timeout, src, flags=re.M)
    rec = Recorder()
    req = type("Req", (), {"user": user or User("AnonymousUser"),
                           "context": {"pending_user": pending} if pending else {}})()
    ctx = {"request": req, "ak_client_ip": ip}
    glb = {"ak_message": rec.message, "ak_logger": Recorder.Logger(rec), "requests": requests_lib.Session()}
    keys = ",".join(ctx)
    code = "def handler(%s):\n%s\nresult = handler(%s)" % (keys, indent(src, "    "), keys)
    old = os.environ.get(env_name)
    if token is None:
        os.environ.pop(env_name, None)
    else:
        os.environ[env_name] = token
    try:
        loc = dict(ctx)
        exec(compile(code, "policy", "exec"), glb, loc)
    finally:
        if old is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = old
    return loc["result"], rec


class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = Mock()
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.srv.script.clear()
        self.srv.seen.clear()

    def ok(self, **kw):
        return run_policy(self.srv.url, **kw)

    def test_compliant_allows_and_sends_bearer(self):
        self.srv.script["ip=198.51.100.7"] = (200, data(), 0, {})
        res, rec = self.ok()
        self.assertIs(res, True)
        self.assertEqual(rec.messages, [])
        self.assertEqual(self.srv.seen[0],
                         ("/api/admin/v1/posture/lookup", "ip=198.51.100.7", "Bearer " + TOKEN))

    def test_denials(self):
        cases = {
            "noncompliant": (200, data(False, "NONCOMPLIANT", reasons=["disk"]), 0, {}),
            "quarantined": (200, data(False, "QUARANTINED"), 0, {}),
            "unknown": (200, data(False, "UNKNOWN", None), 0, {}),
            "ambiguous": (200, data(False, "UNKNOWN", None, ["ambiguous identity"]), 0, {}),
            "allowed true but state not compliant": (200, data(True, "NONCOMPLIANT"), 0, {}),
            "allowed as a string": (200, {"data": {"allowed": "true", "state": "COMPLIANT", "device_id": "x"}}, 0, {}),
            "allowed 1": (200, {"data": {"allowed": 1, "state": "COMPLIANT", "device_id": "x"}}, 0, {}),
            "http 500": (500, {"error": {}}, 0, {}),
            "http 403": (403, {"error": {}}, 0, {}),
            "http 401": (401, {"error": {}}, 0, {}),
            "not json": (200, b"<html>", 0, {}),
            "no data": (200, {"hello": 1}, 0, {}),
            "data is a list": (200, {"data": []}, 0, {}),
            "redirect is not followed": (302, b"", 0, {"Location": self.srv.url + "/ok"}),
            "timeout": (200, data(), 2.0, {}),
        }
        for name, resp in cases.items():
            with self.subTest(name):
                self.srv.script["ip=198.51.100.7"] = resp
                self.srv.script[""] = (200, data(), 0, {})  # where a followed redirect would land
                res, rec = self.ok()
                self.assertIs(res, False, name)
                self.assertEqual(len(rec.messages), 1, name)

    def test_connection_refused_denies(self):
        res, rec = run_policy("http://localhost:1")
        self.assertIs(res, False)
        self.assertEqual(len(rec.messages), 1)

    def test_missing_token_denies_without_calling(self):
        self.assertIs(run_policy(self.srv.url, token=None)[0], False)
        self.assertIs(run_policy(self.srv.url, token="")[0], False)
        self.assertEqual(self.srv.seen, [])

    def test_no_client_address_denies_without_calling(self):
        for ip in (None, ""):
            self.assertIs(run_policy(self.srv.url, ip=ip)[0], False)
        self.assertEqual(self.srv.seen, [])

    def test_bad_identity_setting_denies(self):
        self.assertIs(run_policy(self.srv.url, identity="mac")[0], False)
        self.assertEqual(self.srv.seen, [])

    def test_deny_message_does_not_leak_reasons_or_token(self):
        self.srv.script["ip=198.51.100.7"] = (200, data(False, "NONCOMPLIANT", reasons=["secret reason"]), 0, {})
        _, rec = self.ok()
        self.assertNotIn("secret reason", " ".join(rec.messages))
        self.assertNotIn(TOKEN, repr(rec.logs) + repr(rec.messages))

    def test_user_identity(self):
        self.srv.script["user=alice"] = (200, data(), 0, {})
        self.assertIs(run_policy(self.srv.url, identity="user", pending=User("alice"))[0], True)
        self.assertIs(run_policy(self.srv.url, identity="user", user=User("alice"))[0], True)
        self.srv.script["user=bob"] = (200, data(False, "NONCOMPLIANT"), 0, {})
        self.assertIs(run_policy(self.srv.url, identity="user", user=User("alice"), pending=User("bob"))[0], False)

    def test_user_identity_without_a_user_denies(self):
        self.assertIs(run_policy(self.srv.url, identity="user")[0], False)
        self.assertIs(run_policy(self.srv.url, identity="user", user=User(""))[0], False)
        self.assertEqual(self.srv.seen, [])

    def test_username_is_url_encoded(self):
        self.srv.script["user=a%26ip%3D1.2.3.4"] = (200, data(), 0, {})
        self.assertIs(run_policy(self.srv.url, identity="user", pending=User("a&ip=1.2.3.4"))[0], True)

    def test_ip_and_user_must_be_the_same_device(self):
        self.srv.script["ip=198.51.100.7"] = (200, data(device_id="dev-1"), 0, {})
        self.srv.script["user=alice"] = (200, data(device_id="dev-1"), 0, {})
        self.assertIs(run_policy(self.srv.url, identity="ip_and_user", pending=User("alice"))[0], True)
        self.srv.script["user=alice"] = (200, data(device_id="dev-2"), 0, {})
        self.assertIs(run_policy(self.srv.url, identity="ip_and_user", pending=User("alice"))[0], False)
        self.srv.script["user=alice"] = (200, data(False, "NONCOMPLIANT", device_id="dev-1"), 0, {})
        self.assertIs(run_policy(self.srv.url, identity="ip_and_user", pending=User("alice"))[0], False)

    def test_trailing_slash_in_url(self):
        self.srv.script["ip=198.51.100.7"] = (200, data(), 0, {})
        self.assertIs(run_policy(self.srv.url + "/")[0], True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
