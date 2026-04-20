#!/usr/bin/env python3
"""
ServiceNow Developer Portal - Daily Keep-Alive Login

SAML SP-initiated flow with Okta Classic authn API:

  1. GET  /userlogin.do  ->  302  ->  /login_with_sso.do
         Seeds SN session cookies (JSESSIONID, glide_user_route, etc.)

  2. GET  /login_with_sso.do  ->  200
         Auto-submit HTML form containing SAMLRequest + RelayState.
         Parse but do NOT submit yet — we need the Okta app SSO URL.

  3. POST https://ssosignon.servicenow.com/api/v1/authn
         Body: { username, password }
         Response: { status: "SUCCESS", sessionToken: "..." }

  4. GET  <okta_saml_sso_url>?sessionToken=<token>
         Okta validates the token and returns an auto-submit HTML form
         containing SAMLResponse + RelayState.

  5. POST SAMLResponse to ServiceNow ACS URL  (https://.../navpage.do)
         SN validates the assertion and sets glide_user / glide_user_session.

  6. GET  /api/snc/v1/dev/user_session_info
         Hydrates the developer portal session.
"""

import os
import re
import sys
import json
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

START_URL = (
    "https://developer.servicenow.com/userlogin.do"
    "?relayState=https%3A%2F%2Fdeveloper.servicenow.com%2Fdev.do%5Bobject%20Object%5D"
)

SESSION_HYDRATE = (
    "https://developer.servicenow.com/api/snc/v1/dev/user_session_info"
    "?sysparm_data=%7B%22action%22%3A%22dev.user.session%22"
    "%2C%22data%22%3A%7B%22sysparm_okta%22%3Atrue%7D%7D"
)

USERNAME = os.environ["SNOW_USERNAME"]
PASSWORD = os.environ["SNOW_PASSWORD"]

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def die(msg):
    log.error(msg)
    sys.exit(1)


def parse_auto_submit_form(html, base_url):
    """
    Parse an HTML page that contains a single JS auto-submitting <form>.
    Returns (action_url, {name: value}) for all <input> fields.
    """
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if not form:
        die("Expected an auto-submit form but found none.\n" + html[:500])
    action = urljoin(base_url, form.get("action", ""))
    fields = {
        inp["name"]: inp.get("value", "")
        for inp in form.find_all("input")
        if inp.get("name")
    }
    log.debug("Form action: %s  fields: %s", action, list(fields.keys()))
    return action, fields


def okta_base(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


# ---------------------------------------------------------------------------
# Step 1+2: Fetch the SAML auto-submit form from ServiceNow
# ---------------------------------------------------------------------------

def fetch_saml_form(session):
    """
    Follow the SN login URL through the 302 redirect to /login_with_sso.do.
    Parse the auto-submit form to get:
      - saml_sso_url : the Okta SAML SSO endpoint (form action)
      - saml_fields  : dict of hidden inputs (SAMLRequest, RelayState)
    """
    log.info("Step 1+2 — fetching SAML form")
    resp = session.get(START_URL, headers=BROWSER_HEADERS, timeout=30)
    if resp.status_code != 200:
        die(f"Expected 200 from login_with_sso.do, got {resp.status_code}")

    log.info("Landed on: %s", resp.url)
    saml_sso_url, fields = parse_auto_submit_form(resp.text, resp.url)

    if "SAMLRequest" not in fields:
        die(f"No SAMLRequest in form. Fields present: {list(fields.keys())}")

    log.info("Okta SAML SSO URL: %s", saml_sso_url)
    return saml_sso_url, fields


# ---------------------------------------------------------------------------
# Step 3: Authenticate with Okta classic /api/v1/authn
# ---------------------------------------------------------------------------

def okta_authn(session, okta_base_url):
    """
    POST credentials to the Okta classic authn endpoint.
    On success Okta returns:
        { "status": "SUCCESS", "sessionToken": "20111...Uaj" }
    """
    authn_url = f"{okta_base_url}/api/v1/authn"
    log.info("Step 3 — Okta authn POST to %s", authn_url)

    resp = session.post(
        authn_url,
        json={"username": USERNAME, "password": PASSWORD},
        headers={
            **BROWSER_HEADERS,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": okta_base_url,
        },
        timeout=30,
    )

    log.info("Authn status: %s", resp.status_code)

    if resp.status_code != 200:
        # Surface a clean error — avoid printing the password back
        try:
            err = resp.json()
            die(
                f"Okta authn failed ({resp.status_code}): "
                f"{err.get('errorSummary', resp.text[:300])}"
            )
        except ValueError:
            die(f"Okta authn failed ({resp.status_code}): {resp.text[:300]}")

    data = resp.json()
    status = data.get("status")
    log.info("Okta authn status: %s", status)

    if status == "MFA_ENROLL":
        die(
            "Okta requires MFA enrolment. "
            "Log in interactively once to complete enrolment, then retry."
        )

    if status == "MFA_REQUIRED":
        die(
            "Okta is requiring MFA for this account. "
            "This keep-alive script only supports password authentication. "
            "Disable MFA for this account or use an app password if available."
        )

    if status != "SUCCESS":
        die(f"Okta authn returned unexpected status: {status}\n{json.dumps(data, indent=2)}")

    session_token = data.get("sessionToken")
    if not session_token:
        die(f"Okta authn succeeded but no sessionToken in response: {data}")

    log.info("sessionToken obtained (%.12s...)", session_token)
    return session_token


# ---------------------------------------------------------------------------
# Step 4: Exchange sessionToken for SAMLResponse via the SAML SSO URL
# ---------------------------------------------------------------------------

def exchange_session_token(session, saml_sso_url, session_token):
    """
    GET the Okta SAML SSO URL with the sessionToken appended as a query param.
    Okta validates the token and returns an HTML page with an auto-submit
    form that contains the SAMLResponse destined for the SN ACS URL.
    """
    # Append sessionToken — Okta expects it as a query parameter
    url = f"{saml_sso_url}?sessionToken={session_token}"
    log.info("Step 4 — exchanging sessionToken via %s", saml_sso_url)

    resp = session.get(
        url,
        headers={
            **BROWSER_HEADERS,
            "Referer": okta_base(saml_sso_url),
        },
        allow_redirects=True,
        timeout=30,
    )

    log.info("Token exchange landed on: %s  (status %s)", resp.url, resp.status_code)

    if resp.status_code != 200:
        die(f"Session token exchange failed: {resp.status_code}\n{resp.text[:500]}")

    if "SAMLResponse" not in resp.text:
        log.debug("Token exchange response HTML:\n%.2000s", resp.text)
        die("Expected a SAMLResponse form from Okta but none found.")

    return resp


# ---------------------------------------------------------------------------
# Step 5: POST SAMLResponse back to ServiceNow ACS
# ---------------------------------------------------------------------------

def post_saml_response(session, okta_resp):
    """
    Parse the SAMLResponse auto-submit form from Okta's response and POST
    it to the ServiceNow Assertion Consumer Service URL.
    """
    action, fields = parse_auto_submit_form(okta_resp.text, okta_resp.url)
    log.info("Step 5 — POSTing SAMLResponse to SN ACS: %s", action)

    resp = session.post(
        action,
        data=fields,
        headers={
            **BROWSER_HEADERS,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": okta_resp.url,
        },
        allow_redirects=True,
        timeout=30,
    )

    log.info("ACS POST result: %s  final URL: %s", resp.status_code, resp.url)

    # SN will 302 to /navpage.do or /dev.do after a successful assertion
    if "servicenow.com" not in resp.url:
        log.warning("Unexpected final URL after ACS POST: %s", resp.url)

    return resp


# ---------------------------------------------------------------------------
# Step 6: Hydrate the ServiceNow dev-portal session
# ---------------------------------------------------------------------------

def hydrate_session(session):
    log.info("Step 6 — hydrating SN dev-portal session")
    resp = session.get(
        SESSION_HYDRATE,
        headers={
            **BROWSER_HEADERS,
            "Accept": "application/json",
            "Referer": "https://developer.servicenow.com/",
        },
        timeout=30,
    )

    log.info("Hydration response: %s", resp.status_code)

    if resp.status_code == 200:
        try:
            result = resp.json().get("result", {})
            user = (
                result.get("user_name")
                or result.get("login")
                or result.get("email")
                or result.get("display_name")
            )
            log.info("Session active — logged in as: %s", user or "(user key not in response)")
            log.debug("Full session result: %s", json.dumps(result, indent=2))
        except ValueError:
            log.info("Session hydrated (non-JSON 200).")
        return True

    log.error("Hydration failed: %s\n%.500s", resp.status_code, resp.text)
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)

    # 1+2: Follow SN login URL -> parse SAML auto-submit form
    saml_sso_url, saml_fields = fetch_saml_form(session)

    # Derive the Okta base URL from the SAML SSO endpoint
    okta_base_url = okta_base(saml_sso_url)
    log.info("Okta base URL: %s", okta_base_url)

    # 3: Authenticate with Okta, get sessionToken
    session_token = okta_authn(session, okta_base_url)

    # 4: Exchange sessionToken for SAMLResponse
    okta_resp = exchange_session_token(session, saml_sso_url, session_token)

    # 5: POST SAMLResponse to SN ACS URL
    post_saml_response(session, okta_resp)

    # 6: Hydrate the dev-portal session
    if not hydrate_session(session):
        die("Keep-alive failed — session hydration returned non-200.")

    log.info("Keep-alive complete ✓")


if __name__ == "__main__":
    main()