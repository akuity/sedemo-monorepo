#!/usr/bin/env python3
"""
ServiceNow Developer Portal - Daily Keep-Alive Login

Verified against browser HAR capture. Critical detail:
every post-login API call requires X-UserToken, which is the g_ck
value embedded in the /dev.do page HTML. Without it, API calls
receive no authenticated response and the instance never wakes.

Flow:
  1. GET  /userlogin.do  ->  302  ->  /login_with_sso.do
  2. GET  /login_with_sso.do           (SAML auto-submit form)
  3. POST SAMLRequest to Okta          (seeds Okta session cookies)
  4. POST /api/v1/authn                -> sessionToken
  5. GET  <saml_sso_url>?sessionToken= -> SAMLResponse form
  6. POST SAMLResponse to /navpage.do  -> 302 -> /dev.do
  7. GET  /dev.do                      -> extract g_ck as X-UserToken
  8. GET  user_session_info            (confirm login)
  9. GET  instanceInfo?direct_wake_up=true    (triggers wake when hibernating)
 10. POST instance_backup_validation   (wake signal #2)
 11. GET  check_instance_awake         (wake signal #3 - confirmed in HAR)
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

SN_BASE = "https://developer.servicenow.com"

START_URL = (
    f"{SN_BASE}/userlogin.do"
    "?relayState=https%3A%2F%2Fdeveloper.servicenow.com%2Fdev.do%5Bobject%20Object%5D"
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


def die(msg):
    log.error(msg)
    sys.exit(1)


def parse_auto_submit_form(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if not form:
        die("Expected an auto-submit form but found none.\n" + html[:400])
    action = urljoin(base_url, form.get("action", ""))
    fields = {
        inp["name"]: inp.get("value", "")
        for inp in form.find_all("input")
        if inp.get("name")
    }
    return action, fields


def okta_base(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def api_headers(user_token):
    """Headers used on every authenticated SN API call (confirmed from HAR)."""
    return {
        **BROWSER_HEADERS,
        "Accept": "application/json, text/plain, */*",
        "Referer": f"{SN_BASE}/dev.do",
        "X-UserToken": user_token,
    }


# ---------------------------------------------------------------------------
# Steps 1+2: SN login -> SAML auto-submit form
# ---------------------------------------------------------------------------
def fetch_saml_form(session):
    log.info("Step 1+2 — fetching SAML form")
    resp = session.get(START_URL, headers=BROWSER_HEADERS, timeout=30)
    if resp.status_code != 200:
        die(f"Expected 200, got {resp.status_code}")
    action, fields = parse_auto_submit_form(resp.text, resp.url)
    if "SAMLRequest" not in fields:
        die(f"No SAMLRequest in form. Fields: {list(fields.keys())}")
    log.info("SAML POST target: %s", action)
    return action, fields


# ---------------------------------------------------------------------------
# Step 3: POST SAMLRequest to Okta (seeds Okta cookies; we ignore the page)
# ---------------------------------------------------------------------------
def post_saml_to_okta(session, saml_url, fields):
    log.info("Step 3 — POSTing SAMLRequest to Okta")
    resp = session.post(
        saml_url,
        data=fields,
        headers={
            **BROWSER_HEADERS,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": SN_BASE + "/",
        },
        allow_redirects=True,
        timeout=30,
    )
    if resp.status_code != 200:
        die(f"Expected 200 from Okta, got {resp.status_code}")
    log.info("Okta page: %s", resp.url)
    return resp


# ---------------------------------------------------------------------------
# Step 4: Okta classic authn -> sessionToken
# ---------------------------------------------------------------------------
def okta_authn(session, okta_base_url):
    url = f"{okta_base_url}/api/v1/authn"
    log.info("Step 4 — Okta authn POST")
    resp = session.post(
        url,
        json={"username": USERNAME, "password": PASSWORD},
        headers={
            **BROWSER_HEADERS,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": okta_base_url,
        },
        timeout=30,
    )
    if resp.status_code != 200:
        try:
            err = resp.json()
            die(f"Okta authn failed ({resp.status_code}): {err.get('errorSummary', resp.text[:300])}")
        except ValueError:
            die(f"Okta authn failed ({resp.status_code}): {resp.text[:300]}")

    data = resp.json()
    status = data.get("status")
    log.info("Okta authn status: %s", status)
    if status == "MFA_REQUIRED":
        die("MFA is required — not supported by this script.")
    if status != "SUCCESS":
        die(f"Unexpected Okta authn status: {status}")
    token = data.get("sessionToken")
    if not token:
        die("No sessionToken in Okta authn response.")
    log.info("sessionToken obtained")
    return token


# ---------------------------------------------------------------------------
# Step 5: Exchange sessionToken for SAMLResponse
# ---------------------------------------------------------------------------
def exchange_session_token(session, saml_sso_url, session_token):
    url = f"{saml_sso_url}?sessionToken={session_token}"
    log.info("Step 5 — exchanging sessionToken")
    resp = session.get(
        url,
        headers={**BROWSER_HEADERS, "Referer": okta_base(saml_sso_url)},
        allow_redirects=True,
        timeout=30,
    )
    if resp.status_code != 200 or "SAMLResponse" not in resp.text:
        die(f"Expected SAMLResponse form, got {resp.status_code} at {resp.url}")
    log.info("SAMLResponse form obtained")
    return resp


# ---------------------------------------------------------------------------
# Step 6: POST SAMLResponse to SN ACS -> lands on /dev.do
# ---------------------------------------------------------------------------
def post_saml_response(session, okta_resp):
    action, fields = parse_auto_submit_form(okta_resp.text, okta_resp.url)
    log.info("Step 6 — POSTing SAMLResponse to SN ACS: %s", action)
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
    log.info("ACS result: %s  final URL: %s", resp.status_code, resp.url)
    return resp


# ---------------------------------------------------------------------------
# Step 7: GET /dev.do -> extract g_ck as X-UserToken
# The browser always does this before any API call.
# g_ck is required as X-UserToken on every authenticated API request.
# ---------------------------------------------------------------------------
def fetch_dev_portal(session):
    log.info("Step 7 — fetching /dev.do to obtain g_ck (X-UserToken)")
    resp = session.get(
        f"{SN_BASE}/dev.do",
        headers={**BROWSER_HEADERS, "Referer": SN_BASE + "/"},
        timeout=30,
    )
    if resp.status_code != 200:
        die(f"GET /dev.do returned {resp.status_code}")

    m = re.search(r'g_ck\s*=\s*["\']([a-f0-9]+)["\']', resp.text)
    if not m:
        log.debug("/dev.do HTML snippet:\n%.1000s", resp.text)
        die("Could not extract g_ck from /dev.do")

    g_ck = m.group(1)
    log.info("g_ck (X-UserToken) obtained: %.12s...", g_ck)
    return g_ck


# ---------------------------------------------------------------------------
# Step 8: user_session_info — confirm login
# ---------------------------------------------------------------------------
def confirm_session(session, user_token):
    log.info("Step 8 — confirming session")
    url = (
        f"{SN_BASE}/api/snc/v1/dev/user_session_info"
        "?sysparm_data=%7B%22action%22%3A%22dev.user.session%22"
        "%2C%22data%22%3A%7B%22sysparm_okta%22%3Atrue%7D%7D"
    )
    resp = session.get(url, headers=api_headers(user_token), timeout=30)
    log.info("user_session_info: %s", resp.status_code)
    if resp.status_code == 200:
        result = resp.json().get("result", {})
        log.info(
            "Logged in as: %s  is_logged_in=%s",
            result.get("display_name") or result.get("email", "?"),
            result.get("is_logged_in"),
        )
        return True
    log.warning("user_session_info returned %s", resp.status_code)
    return False


# ---------------------------------------------------------------------------
# Steps 9-11: wake sequence — confirmed from HAR of hibernating instance
#
#  9. GET instanceInfo?direct_wake_up=false  — check state (per HAR)
#  9b GET check_instance_awake               — skip wake if already up
#  10. GET devportal.do?action=instance.hibernate.wake_up&direct_wake_up=true
#          returns {"operation_request_id": "...", "status": "SUCCESS"}
#  11. Poll devportal.do?action=instance.hibernate.is_wake_up_complete&op_req_id=...
#          until isAwake=true
# ---------------------------------------------------------------------------
def wake_instance(session, user_token):
    import time
    import urllib.parse

    hdrs = api_headers(user_token)

    # Step 9: instanceInfo — status check (direct_wake_up=false, per HAR)
    log.info("Step 9 — instanceInfo")
    session.get(
        f"{SN_BASE}/api/snc/v1/dev/instanceInfo"
        "?sysparm_data=%7B%22action%22%3A%22instance.ops.get_instance_info%22"
        "%2C%22data%22%3A%7B%22direct_wake_up%22%3Afalse%7D%7D",
        headers=hdrs, timeout=30,
    )

    # Step 9b: check if already awake — skip wake trigger if so
    log.info("Step 9b — check_instance_awake")
    resp = session.get(
        f"{SN_BASE}/api/snc/v1/dev/check_instance_awake",
        headers=hdrs, timeout=30,
    )
    if resp.status_code == 200:
        result = resp.json().get("result", {})
        is_awake    = result.get("isAwake", False)
        hibernating = result.get("isHibernating", False)
        log.info("isAwake=%s  isHibernating=%s", is_awake, hibernating)
        if is_awake and not hibernating:
            log.info("Instance already awake ✓")
            return True

    # Step 10: trigger wake — devportal.do with instance.hibernate.wake_up
    # This is the actual wake endpoint confirmed in HAR entry [109].
    log.info("Step 10 — triggering wake (devportal.do instance.hibernate.wake_up)")
    resp = session.get(
        f"{SN_BASE}/devportal.do"
        "?sysparm_data=%7B%22action%22%3A%22instance.hibernate.wake_up%22"
        "%2C%22data%22%3A%7B%22direct_wake_up%22%3Atrue%7D%7D",
        headers=hdrs, timeout=30,
    )
    log.info("wake_up: %s  body: %s", resp.status_code, resp.text[:200])

    if resp.status_code != 200:
        log.error("Wake trigger failed: HTTP %s", resp.status_code)
        return False

    try:
        op_req_id = resp.json().get("operation_request_id")
    except ValueError:
        log.error("Wake trigger returned non-JSON: %s", resp.text[:200])
        return False

    if not op_req_id:
        log.error("No operation_request_id in wake response: %s", resp.text[:200])
        return False

    log.info("operation_request_id: %s", op_req_id)

    # Step 11: poll is_wake_up_complete — HAR entry [135]
    log.info("Step 11 — polling is_wake_up_complete")
    poll_url = (
        f"{SN_BASE}/devportal.do?sysparm_data="
        + urllib.parse.quote(json.dumps({
            "action": "instance.hibernate.is_wake_up_complete",
            "data": {"op_req_id": op_req_id},
        }))
    )

    poll_interval = 15
    max_attempts  = 24   # 24 × 15s = 6 minutes
    for attempt in range(1, max_attempts + 1):
        time.sleep(poll_interval)
        resp = session.get(poll_url, headers=hdrs, timeout=30)
        if resp.status_code != 200:
            log.warning("Poll %d: HTTP %s", attempt, resp.status_code)
            continue
        try:
            result = resp.json()
        except ValueError:
            log.warning("Poll %d: non-JSON response", attempt)
            continue

        is_awake  = result.get("isAwake", False)
        op_status = result.get("operation_request_status", "?")
        log.info("Poll %d/%d — isAwake=%s  op_status=%s", attempt, max_attempts, is_awake, op_status)

        if is_awake:
            log.info("Instance is awake ✓")
            return True

    log.error("Instance did not wake within %d seconds.", max_attempts * poll_interval)
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)

    saml_url, saml_fields = fetch_saml_form(session)
    okta_base_url         = okta_base(saml_url)

    post_saml_to_okta(session, saml_url, saml_fields)   # seeds Okta cookies
    session_token = okta_authn(session, okta_base_url)
    okta_resp     = exchange_session_token(session, saml_url, session_token)

    post_saml_response(session, okta_resp)

    user_token = fetch_dev_portal(session)              # critical: get g_ck

    confirm_session(session, user_token)

    if not wake_instance(session, user_token):
        die("Keep-alive failed — check_instance_awake did not return SUCCESS.")

    log.info("Keep-alive complete ✓")


if __name__ == "__main__":
    main()