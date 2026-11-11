import http.cookiejar
import io
import json
from pathlib import Path
import unittest
import urllib.error
import urllib.request

from keycloak_e2e import (
    CALLBACK, ISSUER, CheckFailed, FixtureCookiePolicy, LoginForm, LocalRedirects,
    check_result, failure_reason,
)


class BrowserTests(unittest.TestCase):
    def test_secure_fixture_cookie_has_an_exact_origin_exception(self):
        cookie = http.cookiejar.Cookie(
            version=0, name="AUTH_SESSION_ID", value="synthetic-cookie",
            port=None, port_specified=False, domain="127.0.0.1",
            domain_specified=False, domain_initial_dot=False,
            path="/realms/oidc-cli/", path_specified=True, secure=True,
            expires=None, discard=True, comment=None, comment_url=None, rest={},
        )
        jar = http.cookiejar.CookieJar(policy=FixtureCookiePolicy())
        jar.set_cookie(cookie)
        for target, expected in (
            (ISSUER + "/login-actions/authenticate", True),
            ("http://127.0.0.1:8081/realms/oidc-cli/login", False),
            ("http://127.0.0.1:42813/realms/oidc-cli/login", False),
            ("http://localhost:8080/realms/oidc-cli/login", False),
            ("http://example.com:8080/realms/oidc-cli/login", False),
            ("http://127.0.0.1:8080/unrelated-path", False),
        ):
            with self.subTest(target=target):
                request = urllib.request.Request(target)
                jar.add_cookie_header(request)
                self.assertEqual(request.has_header("Cookie"), expected)

    def test_failure_diagnostics_do_not_echo_sensitive_data(self):
        secret = "sensitive-token-or-url"
        for error in (
            ValueError(secret), CheckFailed(secret),
            urllib.error.HTTPError(secret, 400, secret, {}, None),
        ):
            self.assertNotIn(secret, failure_reason(error))
        self.assertEqual(failure_reason(CheckFailed("token_invalid")), "CLI returned token_invalid")
        self.assertEqual(
            failure_reason(urllib.error.HTTPError(secret, 400, secret, {}, None)), "provider HTTP 400"
        )
        error = urllib.error.HTTPError(
            ISSUER, 400, secret, {}, io.BytesIO(("Cookie not found " + secret).encode())
        )
        self.assertEqual(failure_reason(error), "provider HTTP 400 (Cookie not found)")

    def test_cli_errors_are_allowlisted_for_diagnostics(self):
        for code in ("token_invalid", "sensitive-token"):
            with self.subTest(code=code), self.assertRaises(CheckFailed) as raised:
                check_result({"ok": False, "error": {"code": code}}, 3)
            self.assertNotIn("sensitive-token", failure_reason(raised.exception))

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
