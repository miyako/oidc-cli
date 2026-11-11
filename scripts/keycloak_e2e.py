#!/usr/bin/env python3
"""Optional real public-client login against the disposable Keycloak fixture."""

import argparse
import http.cookiejar
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


ISSUER = "http://127.0.0.1:8080/realms/oidc-cli"
CALLBACK = "http://127.0.0.1:42813/callback"

CLI_ERRORS = {
    "invalid_input", "discovery_failed", "listener_failed", "browser_failed",
    "oauth_error", "token_exchange_failed", "token_invalid", "timeout",
    "cancelled", "internal_error",
}


class CheckFailed(ValueError):
    pass


def failure_reason(error):
    if isinstance(error, CheckFailed):
        if error.args and error.args[0] in CLI_ERRORS:
            return "CLI returned " + error.args[0]
        if error.args == ("login_form_missing",):
            return "expected Keycloak login form was not present"
    if isinstance(error, urllib.error.HTTPError):
        if isinstance(error.code, int) and 100 <= error.code <= 599:
            return f"HTTP {error.code}"
        return "HTTP error"
    if isinstance(error, queue.Empty):
        return "authorization event was not received"
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return "deadline exceeded"
    return "invalid response or request failed"


def check_result(result, returncode):
    if not isinstance(result, dict):
        raise CheckFailed("invalid_result")
    if returncode != 0 or result.get("ok") is not True:
        error = result.get("error")
        code = error.get("code") if isinstance(error, dict) else None
        raise CheckFailed(code if isinstance(code, str) and code in CLI_ERRORS else "invalid_result")
    identity = result.get("identity")
    if (result.get("protocol_version") != 1 or not isinstance(identity, dict)
            or identity.get("issuer") != ISSUER or not identity.get("subject")):
        raise CheckFailed("invalid_result")


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == "kc-form-login":
            self.action = attrs.get("action")


class LocalRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def __init__(self, callback):
        self.origins = {
            urllib.parse.urlsplit(ISSUER).netloc,
            urllib.parse.urlsplit(callback).netloc,
        }

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "http" or parsed.netloc not in self.origins:
            raise ValueError("unexpected redirect origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("build/oidc-cli"))
    args = parser.parse_args()
    request = {
        "protocol_version": 1,
        "issuer": ISSUER,
        "client_id": "oidc-cli",
        "listen_address": urllib.parse.urlsplit(CALLBACK).netloc,
        "scopes": ["openid", "profile", "email"],
        "open_browser": False,
        "allow_insecure_loopback_http": True,
        "include_tokens": True,
        "timeout_seconds": 60,
        "http_timeout_seconds": 10,
        "parent_pid": os.getpid(),
    }
    process = subprocess.Popen([str(args.binary.resolve()), "authenticate"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    events = queue.Queue(maxsize=1)
    diagnostics = []

    def read_event():
        while True:
            line = process.stderr.readline(65537)
            if not line:
                return
            diagnostics.append(line)
            if len(line) > 65536 or len(diagnostics) > 8:
                return
            try:
                event = json.loads(line)
                if event.get("event") == "authorization_required" and events.empty():
                    events.put_nowait(event)
            except (ValueError, AttributeError, queue.Full):
                return

    reader = threading.Thread(target=read_event, daemon=True)
    reader.start()
    deadline = time.monotonic() + 75
    stage = "authorization event"
    try:
        process.stdin.write(json.dumps(request) + "\n")
        process.stdin.close()
        process.stdin = None
        event = events.get(timeout=15)
        if event.get("protocol_version") != 1:
            raise ValueError("unexpected event protocol")
        authorization_url = event["authorization_url"]
        parsed = urllib.parse.urlsplit(authorization_url)
        if parsed.scheme != "http" or parsed.netloc != "127.0.0.1:8080":
            raise ValueError("unexpected authorization origin")
        parameters = urllib.parse.parse_qs(parsed.query)
        callback = parameters["redirect_uri"][0]
        if callback != CALLBACK:
            raise ValueError("unexpected callback")
        if parameters.get("code_challenge_method") != ["S256"]:
            raise ValueError("PKCE S256 not requested")
        browser = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            LocalRedirects(callback),
        )

        def fetch(url, data=None):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("E2E deadline reached")
            with browser.open(url, data, timeout=min(10, remaining)) as response:
                return response.read(1024 * 1024).decode("utf-8")

        form = LoginForm()
        stage = "authorization page"
        form.feed(fetch(authorization_url))
        if not form.action:
            raise CheckFailed("login_form_missing")
        action = urllib.parse.urljoin(authorization_url, form.action)
        parsed_action = urllib.parse.urlsplit(action)
        if parsed_action.scheme != "http" or parsed_action.netloc != "127.0.0.1:8080":
            raise ValueError("unexpected credential destination")
        credentials = urllib.parse.urlencode({
            "username": "test-user",
            "password": "test-password-not-for-production",
            "credentialId": "",
        }).encode("ascii")
        stage = "login submission"
        fetch(action, credentials)
        stage = "CLI result"
        process.wait(timeout=max(1, deadline - time.monotonic()))
        stdout = process.stdout.read()
        reader.join(timeout=2)
        result = json.loads(stdout)
        check_result(result, process.returncode)
        tokens = result.get("tokens", {})
        if not tokens.get("id_token") or not tokens.get("access_token"):
            raise ValueError("requested tokens missing")
        if any(token in "".join(diagnostics)
               for token in (tokens["id_token"], tokens["access_token"])):
            raise ValueError("token leaked to stderr")
        print("Keycloak E2E passed: code + S256 + loopback callback + verified identity.")
        return 0
    except (OSError, ValueError, KeyError, queue.Empty, subprocess.TimeoutExpired) as error:
        # Never print provider responses, URLs, credentials, or token-bearing output.
        print(f"Keycloak E2E failed at {stage}: {failure_reason(error)}.", file=sys.stderr)
        return 1
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


if __name__ == "__main__":
    sys.exit(main())
