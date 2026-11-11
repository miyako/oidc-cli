import json
from pathlib import Path
import unittest
import urllib.request

from keycloak_e2e import CALLBACK, LoginForm, LocalRedirects


class BrowserTests(unittest.TestCase):
    def test_fixture_registers_exact_callback(self):
        fixture = Path(__file__).resolve().parents[1] / "testdata/keycloak/realm.json"
        realm = json.loads(fixture.read_text())
        self.assertEqual(realm["clients"][0]["redirectUris"], [CALLBACK])

    def test_login_form_decodes_html_action(self):
        form = LoginForm()
        form.feed('<form id="kc-form-login" action="/login?a=1&amp;b=2"></form>')
        self.assertEqual(form.action, "/login?a=1&b=2")

    def test_redirect_rejects_remote_destination(self):
        redirects = LocalRedirects("http://127.0.0.1:42813/callback")
        request = urllib.request.Request("http://127.0.0.1:8080/login")
        for destination in ("https://example.com/", "http://127.0.0.1:8888/",
                            "http://127.0.0.1:42813@example.com/"):
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                redirects.redirect_request(request, None, 302, "Found", {}, destination)


if __name__ == "__main__":
    unittest.main()
