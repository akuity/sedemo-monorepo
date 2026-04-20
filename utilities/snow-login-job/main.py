#!/usr/bin/env python3
"""
ServiceNow Developer Portal - Daily Keep-Alive Login
Logs into developer.servicenow.com to prevent instance hibernation.
"""

import os
import sys
import logging
from typing import Optional
import requests
from bs4 import BeautifulSoup

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

PORTAL_BASE = "https://developer.servicenow.com"
LOGIN_PAGE  = f"{PORTAL_BASE}/dev.do#!/login"
LOGIN_POST  = f"{PORTAL_BASE}/api/now/devportal/login"

USERNAME = os.environ["SNOW_USERNAME"]
PASSWORD = os.environ["SNOW_PASSWORD"]


def get_csrf_token(session: requests.Session) -> Optional[str]:
    """
    Fetch the login page and extract the CSRF/XSRF token.
    ServiceNow sets it as the XSRF-TOKEN cookie on Angular-based portals,
    but also falls back to a <meta> tag or hidden input in the HTML.
    """
    log.info("Fetching login page: %s", LOGIN_PAGE)
    resp = session.get(LOGIN_PAGE, timeout=30)
    resp.raise_for_status()

    # 1. XSRF-TOKEN cookie (most common)
    xsrf_cookie = session.cookies.get("XSRF-TOKEN")
    if xsrf_cookie:
        log.info("CSRF token found in cookie.")
        return xsrf_cookie

    # 2. <meta name="csrf-token"> or hidden form input
    soup = BeautifulSoup(resp.text, "html.parser")

    meta = soup.find("meta", {"name": lambda n: n and "csrf" in n.lower()})
    if meta and meta.get("content"):
        log.info("CSRF token found in <meta> tag.")
        return meta["content"]

    hidden = soup.find(
        "input",
        {"name": lambda n: n and ("csrf" in n.lower() or "xsrf" in n.lower())},
    )
    if hidden and hidden.get("value"):
        log.info("CSRF token found in hidden form field.")
        return hidden["value"]

    log.warning("No CSRF token found — proceeding without one.")
    return None


def login(session: requests.Session, csrf_token: Optional[str]) -> bool:
    """POST credentials to the login endpoint."""
    headers = {
        "Content-Type": "application/json",
        "Referer": LOGIN_PAGE,
        "X-Requested-With": "XMLHttpRequest",
    }
    if csrf_token:
        headers["X-XSRF-TOKEN"] = csrf_token
        headers["X-CSRF-TOKEN"]  = csrf_token

    payload = {
        "user_name": USERNAME,
        "user_password": PASSWORD,
        "remember_me": False,
    }

    log.info("Posting credentials to %s", LOGIN_POST)
    resp = session.post(LOGIN_POST, json=payload, headers=headers, timeout=30)
    log.info("Response status: %s", resp.status_code)

    if resp.status_code == 200:
        try:
            body = resp.json()
            if "error" in body:
                log.error("Login failed — API error: %s", body["error"])
                return False
            log.info("Login successful. Response keys: %s", list(body.keys()))
            return True
        except ValueError:
            # Non-JSON 200 is fine for redirect-based flows
            log.info("Login successful (non-JSON 200 response).")
            return True

    if resp.status_code in (301, 302):
        log.info("Login successful (redirect).")
        return True

    log.error("Unexpected status %s. Body: %.500s", resp.status_code, resp.text)
    return False


def verify_logged_in(session: requests.Session) -> bool:
    """Confirm authentication by hitting the instance management endpoint."""
    check_url = f"{PORTAL_BASE}/api/now/devportal/instance"
    log.info("Verifying session via %s", check_url)
    resp = session.get(check_url, timeout=30)
    if resp.status_code == 200:
        log.info("Session verification passed.")
        return True
    log.warning("Session verification returned %s.", resp.status_code)
    return False


def main():
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    })

    csrf_token = get_csrf_token(session)
    success    = login(session, csrf_token)

    if not success:
        log.error("Login attempt failed.")
        sys.exit(1)

    verify_logged_in(session)
    log.info("Keep-alive complete.")


if __name__ == "__main__":
    main()