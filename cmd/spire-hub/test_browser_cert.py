"""Tests for the spire-hub browser certificate enrolment code.

They run the real certutil and pk12util against a temporary HOME (never the real
~/.pki) and a fake IPC client that signs CSRs with the openssl command line tool.
They are skipped when those tools are missing.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("spire_hub", os.path.join(HERE, "spire-hub.py"))
hub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hub)

HAVE_TOOLS = all(shutil.which(t) for t in ("certutil", "pk12util", "openssl"))


class FakeIPC:
    """Stands in for spired: signs the CSR it is given with a throwaway device CA."""

    def __init__(self, workdir, user="alice", enabled=True, eligible=True):
        self.workdir = workdir
        self.clock = lambda: datetime.now(timezone.utc)
        self.user = user
        self.enabled = enabled
        self.eligible = eligible
        self.issued = 0
        self.csrs = []
        self.fail = None
        self.wrong_key = False
        self.ca_key = os.path.join(workdir, "ca.key")
        self.ca_pem = os.path.join(workdir, "ca.pem")
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", self.ca_key],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "req", "-x509", "-new", "-key", self.ca_key, "-subj", "/CN=SpireUEM Device CA",
                        "-days", "30", "-out", self.ca_pem], check=True, capture_output=True)

    def _stamp(self, seconds):
        return (self.clock() + timedelta(seconds=seconds)).strftime("%Y%m%d%H%M%SZ")

    def browser_cert_config(self):
        return {"enabled": self.enabled, "eligible": self.eligible}

    def browser_cert_issue(self, csr_pem):
        if self.fail:
            raise RuntimeError(self.fail)
        self.csrs.append(csr_pem)
        csr = os.path.join(self.workdir, "req.pem")
        if self.wrong_key:
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out",
                            os.path.join(self.workdir, "other.key")], check=True, capture_output=True)
            subprocess.run(["openssl", "req", "-new", "-key", os.path.join(self.workdir, "other.key"),
                            "-subj", "/CN=x", "-out", csr], check=True, capture_output=True)
        else:
            with open(csr, "w") as fh:
                fh.write(csr_pem)
        self.issued += 1
        out = os.path.join(self.workdir, f"leaf{self.issued}.pem")
        ext = os.path.join(self.workdir, "ext.cnf")
        with open(ext, "w") as fh:
            fh.write("extendedKeyUsage=clientAuth\n")
        subprocess.run(["openssl", "x509", "-req", "-in", csr, "-CA", self.ca_pem, "-CAkey", self.ca_key,
                        "-set_serial", str(100 + self.issued), "-not_before", self._stamp(-60), "-not_after",
                        self._stamp(7 * 86400), "-out", out, "-extfile", ext,
                        "-subj", f"/CN={self.user}@device-1"], check=True, capture_output=True)
        with open(out) as fh:
            leaf = fh.read()
        with open(self.ca_pem) as fh:
            ca = fh.read()
        return {"user": self.user, "certificate_pem": leaf, "device_ca_pem": ca, "not_after": ""}


@unittest.skipUnless(HAVE_TOOLS, "certutil, pk12util and openssl are required")
class BrowserCertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="spire-hub-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = os.path.join(self.tmp, "home")
        self.run_dir = os.path.join(self.tmp, "run")
        os.makedirs(self.home)
        os.makedirs(self.run_dir, mode=0o700)
        self.old_state = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = os.path.join(self.home, ".local", "state")
        self.addCleanup(self._restore_env)
        self.ipc = FakeIPC(self.tmp)
        self.now_offset = timedelta(0)
        self.ipc.clock = lambda: datetime.now(timezone.utc) + self.now_offset
        self.mgr = self._manager()

    def _restore_env(self):
        if self.old_state is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = self.old_state

    def _manager(self, certutil=None):
        real_now = hub.datetime.now
        mgr = hub.BrowserCertManager(
            self.ipc, home=self.home, certutil=certutil, runtime_dir=self.run_dir,
            now=lambda: real_now(hub.timezone.utc) + self.now_offset,
        )
        return mgr

    def nicks(self, dbdir=None, prefix=hub.NICK_PREFIX):
        return self.mgr.list_nicks(dbdir or self.mgr.nssdb, prefix)

    def keys(self, dbdir=None):
        return self.mgr.key_ids(dbdir or self.mgr.nssdb)

    # ------------------------------------------------------------------------------------

    def test_enrol_puts_key_and_certificate_in_nss(self):
        self.assertEqual(self.mgr.sync(), "ok")
        nicks = self.nicks()
        self.assertEqual(len(nicks), 1)
        keys = self.keys()
        self.assertEqual(list(keys.values()), nicks, "the one key must be bound to the one certificate")
        self.assertEqual(len(self.ipc.csrs), 1)
        self.assertNotIn("PRIVATE", self.ipc.csrs[0], "only a CSR may be sent")
        # The CA is present without trust.
        self.assertEqual(len(self.nicks(prefix=hub.CA_NICK_PREFIX)), 1)
        listing = self.mgr._certutil_run(self.mgr.nssdb, "-L").stdout
        ca_line = [ln for ln in listing.splitlines() if ln.startswith(hub.CA_NICK_PREFIX)][0]
        self.assertTrue(ca_line.rstrip().endswith(",,"), ca_line)
        state = self.mgr.read_state()
        self.assertEqual(state["status"], "ok")
        self.assertTrue(state["not_after"])
        self.assertIn("valid until", hub.browser_cert_status_text(state))
        # The database is the user's own, mode 0700 directory.
        self.assertEqual(os.stat(self.mgr.nssdb).st_mode & 0o777, 0o700)

    def test_second_sync_does_not_reissue(self):
        self.mgr.sync()
        self.assertEqual(self.mgr.sync(), "ok")
        self.assertEqual(self.ipc.issued, 1)

    def test_renews_after_two_thirds_of_lifetime(self):
        self.mgr.sync()
        old = self.nicks()[0]
        self.now_offset = timedelta(days=4)  # 7-day certificate: 2/3 is about 4.7 days
        self.mgr.sync()
        self.assertEqual(self.ipc.issued, 1, "not due yet")
        self.now_offset = timedelta(days=5)
        self.assertEqual(self.mgr.sync(), "ok")
        self.assertEqual(self.ipc.issued, 2)
        nicks = self.nicks()
        self.assertEqual(len(nicks), 1)
        self.assertNotEqual(nicks[0], old, "the old certificate must be replaced")
        self.assertEqual(list(self.keys().values()), nicks, "the old key must be gone too")

    def test_expired_certificate_is_replaced(self):
        self.mgr.sync()
        self.now_offset = timedelta(days=8)
        self.assertEqual(self.mgr.sync(), "ok")
        self.assertEqual(self.ipc.issued, 2)
        self.assertEqual(len(self.nicks()), 1)

    def test_other_certificates_and_keys_are_never_touched(self):
        # A certificate the user (or another tool) put in their database, with its own key.
        self.mgr.ensure_db()
        csr = os.path.join(self.tmp, "corp.csr")
        noise = os.path.join(self.tmp, "noise")
        with open(noise, "wb") as fh:
            fh.write(os.urandom(64))
        self.mgr._certutil_run(self.mgr.nssdb, "-R", "-s", "CN=corp vpn", "-k", "ec", "-q", "nistp256",
                               "-a", "-o", csr, "-z", noise)
        crt = os.path.join(self.tmp, "corp.pem")
        subprocess.run(["openssl", "x509", "-req", "-in", csr, "-CA", self.ipc.ca_pem, "-CAkey", self.ipc.ca_key,
                        "-set_serial", "7", "-days", "30", "-out", crt, "-subj", "/CN=corp vpn"],
                       check=True, capture_output=True)
        self.mgr._certutil_run(self.mgr.nssdb, "-A", "-n", "Corp VPN", "-t", "u,u,u", "-i", crt)
        # And an orphan key nobody has a certificate for.
        self.mgr._certutil_run(self.mgr.nssdb, "-R", "-s", "CN=orphan", "-k", "ec", "-q", "nistp256",
                               "-a", "-o", os.path.join(self.tmp, "orphan.csr"), "-z", noise)
        before_keys = set(self.keys())
        self.mgr.sync()
        self.now_offset = timedelta(days=8)
        self.mgr.sync()
        self.assertIn("Corp VPN", self.mgr.list_nicks(self.mgr.nssdb, "Corp"))
        after = self.keys()
        self.assertTrue(before_keys <= set(after), "a key SpireUEM did not create was removed")
        self.assertEqual(after[next(k for k in before_keys if after[k] == "Corp VPN")], "Corp VPN")

    def test_issue_failure_leaves_no_key_behind(self):
        self.ipc.fail = "server returned HTTP 502"
        self.assertEqual(self.mgr.sync(), "error")
        self.assertEqual(self.keys(), {}, "a key was generated and not cleaned up")
        self.assertEqual(self.nicks(), [])
        self.assertIn("502", self.mgr.read_state()["message"])
        self.ipc.fail = None
        self.assertEqual(self.mgr.sync(), "ok")

    def test_certificate_for_another_key_is_rejected(self):
        self.ipc.wrong_key = True
        self.assertEqual(self.mgr.sync(), "error")
        self.assertEqual(self.nicks(), [], "a certificate that does not match the key was kept")
        self.assertEqual(self.keys(), {})

    def test_failed_renewal_keeps_the_working_certificate(self):
        self.mgr.sync()
        old = self.nicks()
        self.now_offset = timedelta(days=5)
        self.ipc.fail = "unreachable"
        self.assertEqual(self.mgr.sync(), "error")
        self.assertEqual(self.nicks(), old)
        self.assertEqual(list(self.keys().values()), old)

    def test_missing_certutil_is_reported_once(self):
        mgr = self._manager(certutil="/nonexistent/certutil")
        self.assertEqual(mgr.sync(), "missing_certutil")
        self.assertIn("libnss3-tools", mgr.read_state()["message"])
        self.assertIn("libnss3-tools", hub.browser_cert_status_text(mgr.read_state()))
        self.assertTrue(mgr._warned_missing)
        self.assertEqual(self.ipc.issued, 0)
        self.assertFalse(os.path.exists(mgr.nssdb), "nothing may be created without certutil")

    def test_disabled_and_ineligible_do_nothing(self):
        self.ipc.enabled = False
        self.assertEqual(self.mgr.sync(), "disabled")
        self.ipc.enabled, self.ipc.eligible = True, False
        self.assertEqual(self.mgr.sync(), "not_eligible")
        self.assertEqual(self.ipc.issued, 0)
        self.assertFalse(os.path.exists(self.mgr.nssdb))

    def test_firefox_profile_gets_the_same_certificate_and_key(self):
        prof = os.path.join(self.home, ".mozilla", "firefox", "abc.default")
        os.makedirs(prof)
        subprocess.run(["certutil", "-N", "-d", f"sql:{prof}", "--empty-password"], check=True, capture_output=True)
        argv_log = []
        pw_seen = []
        real_run = self.mgr._run

        def spy(argv, check=True, input_text=None):
            argv_log.append(list(argv))
            if "-w" in argv:
                with open(argv[argv.index("-w") + 1]) as fh:
                    pw_seen.append(fh.read())
            return real_run(argv, check=check, input_text=input_text)

        self.mgr._run = spy
        self.assertEqual(self.mgr.sync(), "ok")
        nick = self.nicks()[0]
        self.assertIn(nick, self.mgr.key_ids(prof).values(), "the profile has no bound key")
        # The one-time password never appears on a command line, and nothing is left behind.
        self.assertTrue(pw_seen and all(pw_seen))
        for argv in argv_log:
            for part in argv:
                for pw in pw_seen:
                    self.assertNotIn(pw, part)
        self.assertEqual(os.listdir(self.run_dir), [], "temporary files were left in the runtime dir")
        # A renewal replaces the profile's certificate too.
        self.now_offset = timedelta(days=5)
        self.mgr._run = real_run
        self.assertEqual(self.mgr.sync(), "ok")
        new = self.nicks()[0]
        self.assertNotEqual(new, nick)
        self.assertEqual(self.mgr.list_nicks(prof, hub.NICK_PREFIX), [new])
        self.assertEqual(list(self.mgr.key_ids(prof).values()), [new])

    def test_firefox_profile_with_primary_password_is_reported_not_fatal(self):
        prof = os.path.join(self.home, ".mozilla", "firefox", "locked.default")
        os.makedirs(prof)
        pwf = os.path.join(self.tmp, "mp")
        with open(pwf, "w") as fh:
            fh.write("secret\n")
        subprocess.run(["certutil", "-N", "-d", f"sql:{prof}", "-f", pwf], check=True, capture_output=True)
        self.assertEqual(self.mgr.sync(), "ok")
        state = self.mgr.read_state()
        self.assertIn("Firefox profile not updated", state["message"])
        self.assertEqual(len(self.nicks()), 1, "the main database still has its certificate")


if __name__ == "__main__":
    unittest.main()
