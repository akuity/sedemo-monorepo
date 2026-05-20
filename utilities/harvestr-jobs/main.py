"""
harvestr_revenue.py
-------------------
Aggregates company "Lost Revenue" attribute values across open Harvestr
Discoveries, then reports any discrepancy vs. the stored total in Discovery
custom field REVENUE_FIELD_ID.

Usage:
    HARVESTR_API_TOKEN=<token> python harvestr_revenue.py

Dependencies:
    pip install requests
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import sys
import time
from collections import deque
from typing import Any, Generator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ── Configuration ─────────────────────────────────────────────────────────────

BASE_URL = "https://rest.harvestr.io/v1"
API_TOKEN = os.environ.get("HARVESTR_API_TOKEN", "")

GRAPHQL_URL = "https://graphql.harvestr.io/graphql"
# JWT Bearer token from an active Harvestr browser session.
# In Chrome: DevTools → Application → Local Storage → app.harvestr.io → copy the token.
JWT_TOKEN = os.environ.get("HARVESTR_JWT_TOKEN", "")

# Set to "0" to actually write updates; defaults to dry-run for safety.
DRY_RUN = os.environ.get("HARVESTR_DRY_RUN", "1") != "0"

# ── Endpoint paths (relative to BASE_URL) ─────────────────────────────────────
PATH_DISCOVERIES = "/discovery"
PATH_FEEDBACK = "/feedback"
PATH_MESSAGE = "/message"          # /{id} appended for single-item fetch
PATH_USER = "/user"                # /{id} appended for single-item fetch
PATH_COMPANY_ATTRS = "/company"    # /{id}/attribute-value appended at call site

# Company attribute ID for "Lost Revenue"
LOST_REVENUE_ATTR_ID = "cmn1xnbdw02mqmi4wrv6e49i0"

# Discovery custom field ID that stores the aggregated revenue total
REVENUE_FIELD_ID = "mp070wIUv"

# Populate with discoveryStateId values that represent "open" to limit scope.
# Leave empty to process all discoveries regardless of state.
OPEN_STATE_IDS: list[str] = []

# Set to a directory path to persist raw API responses as JSON files.
# On subsequent runs the cached file is returned instead of calling the API.
# Delete individual files (or the whole directory) to force a fresh fetch.
# Example: HARVESTR_DEBUG_DIR=./debug python harvestr_revenue.py
DEBUG_DIR = os.environ.get("HARVESTR_DEBUG_DIR", "")

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)

# ── Rate limiter ──────────────────────────────────────────────────────────────
# Harvestr limits: 10 req/s · 5,000 req/min · 50,000 req/day
# We enforce the per-second ceiling here; the daily remaining is tracked via
# response headers and triggers a warning when low.

_DAILY_WARN_THRESHOLD = 500  # warn when fewer than this many daily calls remain


class _RateLimiter:
    """Sliding-window limiter that enforces at most `max_rps` requests per second."""

    def __init__(self, max_rps: int = 10) -> None:
        self._max = max_rps
        self._window: deque[float] = deque()

    def acquire(self) -> None:
        now = time.monotonic()
        # Drop timestamps that have aged out of the 1-second window
        while self._window and self._window[0] <= now - 1.0:
            self._window.popleft()
        if len(self._window) >= self._max:
            # Sleep until the oldest call falls outside the window
            wait = self._window[0] + 1.0 - now
            if wait > 0:
                log.debug("Per-second rate limit reached — sleeping %.3fs", wait)
                time.sleep(wait)
            now = time.monotonic()
            while self._window and self._window[0] <= now - 1.0:
                self._window.popleft()
        self._window.append(time.monotonic())


_limiter = _RateLimiter(max_rps=10)

# ── HTTP session ──────────────────────────────────────────────────────────────

_session: requests.Session | None = None


def _get_session() -> requests.Session:
    global _session
    if _session is None:
        s = requests.Session()
        s.headers.update(
            {
                "Accept": "application/json",
                "X-Harvestr-Private-App-Token": API_TOKEN,
            }
        )
        retry = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            respect_retry_after_header=True,  # honour Retry-After on 429
        )
        s.mount("https://", HTTPAdapter(max_retries=retry))
        _session = s
    return _session


def _check_rate_limit_headers(resp: requests.Response) -> None:
    """Log a warning when the daily quota is running low."""
    remaining_raw = resp.headers.get("X-Rate-Limit-Remaining")
    if remaining_raw is None:
        return
    try:
        remaining = int(remaining_raw)
    except ValueError:
        return
    if remaining <= _DAILY_WARN_THRESHOLD:
        reset_raw = resp.headers.get("X-Rate-Limit-Reset")
        reset_info = ""
        if reset_raw:
            try:
                reset_dt = datetime.datetime.utcfromtimestamp(int(reset_raw))
                reset_info = f" — resets at {reset_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC"
            except (ValueError, OSError):
                pass
        log.warning("Daily rate limit low: %d requests remaining%s", remaining, reset_info)


def _debug_filename(path: str, params: dict | None) -> str:
    safe_path = path.strip("/").replace("/", "_")
    params_hash = hashlib.md5(
        json.dumps(params or {}, sort_keys=True).encode()
    ).hexdigest()[:8]
    return f"{safe_path}_{params_hash}.json"


def _load_debug(path: str, params: dict | None) -> Any | None:
    if not DEBUG_DIR:
        return None
    filepath = os.path.join(DEBUG_DIR, _debug_filename(path, params))
    if not os.path.exists(filepath):
        return None
    with open(filepath) as fh:
        payload = json.load(fh)
    log.debug("Cache hit  → %s", filepath)
    return payload["response"]


def _save_debug(path: str, params: dict | None, data: Any) -> None:
    if not DEBUG_DIR:
        return
    os.makedirs(DEBUG_DIR, exist_ok=True)
    filepath = os.path.join(DEBUG_DIR, _debug_filename(path, params))
    payload = {"path": path, "params": params, "response": data}
    with open(filepath, "w") as fh:
        json.dump(payload, fh, indent=2, default=str)
    log.debug("Cache save → %s", filepath)


def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    cached = _load_debug(path, params)
    if cached is not None:
        return cached
    _limiter.acquire()
    resp = _get_session().get(f"{BASE_URL}{path}", params=params, timeout=30)
    resp.raise_for_status()
    _check_rate_limit_headers(resp)
    data = resp.json()
    _save_debug(path, params, data)
    return data


def _paginate(
    path: str,
    items_key: str,
    params: dict[str, Any] | None = None,
) -> Generator[dict, None, None]:
    """Yield every item from a paginated endpoint (100 per page)."""
    p: dict[str, Any] = {**(params or {}), "per_page": 100}
    offset = 0
    while True:
        p["offset"] = offset
        data = _get(path, p)
        # Discoveries return a plain list; others return {"<key>": [...]}
        items: list[dict] = data if isinstance(data, list) else data.get(items_key, [])
        yield from items
        if len(items) < 100:
            break
        offset += 100


# ── Step 1: Fetch all open discoveries ───────────────────────────────────────


def fetch_discoveries() -> list[dict]:
    """
    Return all open discoveries with their custom field values loaded.

    If OPEN_STATE_IDS is populated, only discoveries whose discoveryStateId
    appears in that set are returned.  Leave it empty to include every discovery.
    """
    log.info("Step 1  fetching discoveries …")
    items = list(
        _paginate(PATH_DISCOVERIES, "discoveries", {"select": "discoveryfields"})
    )
    if OPEN_STATE_IDS:
        open_set = set(OPEN_STATE_IDS)
        items = [d for d in items if d.get("discoveryStateId") in open_set]
        log.info("        %d discoveries after state filter", len(items))
    else:
        log.info("        %d discoveries loaded (no state filter)", len(items))
    return items


# ── Step 2: Feedback per discovery ───────────────────────────────────────────


def fetch_feedback(discoveries: list[dict]) -> dict[str, list[dict]]:
    """Return {discovery_id: [feedback, …]} for every discovery."""
    log.info("Step 2  fetching feedback for %d discoveries …", len(discoveries))
    result: dict[str, list[dict]] = {}
    for disc in discoveries:
        did = disc["id"]
        result[did] = list(_paginate(PATH_FEEDBACK, "feedbacks", {"discoveryId": did}))
    total_fb = sum(len(v) for v in result.values())
    log.info("        %d total feedback items", total_fb)
    return result


# ── Step 3: Messages → requester IDs ─────────────────────────────────────────


def fetch_requesters(
    discovery_feedback: dict[str, list[dict]],
) -> tuple[dict[str, str], dict[str, set[str]]]:
    """
    Retrieve each unique message once and extract its requesterId.

    Returns:
        message_requester    {message_id: requester_id}
        discovery_requesters {discovery_id: {requester_id, …}}
    """
    log.info("Step 3  resolving requester IDs from messages …")

    unique_message_ids: set[str] = {
        fb["messageId"]
        for feedbacks in discovery_feedback.values()
        for fb in feedbacks
        if fb.get("messageId")
    }
    log.info("        fetching %d unique messages …", len(unique_message_ids))

    message_requester: dict[str, str] = {}
    for mid in unique_message_ids:
        msg = _get(f"{PATH_MESSAGE}/{mid}").get("message", {})
        rid = msg.get("requesterId")
        if rid:
            message_requester[mid] = rid
        else:
            log.debug("        message %s has no requesterId", mid)

    discovery_requesters: dict[str, set[str]] = {
        did: {
            message_requester[fb["messageId"]]
            for fb in feedbacks
            if fb.get("messageId") and fb["messageId"] in message_requester
        }
        for did, feedbacks in discovery_feedback.items()
    }

    unique_requesters = {r for rs in discovery_requesters.values() for r in rs}
    log.info("        %d unique requesters identified", len(unique_requesters))
    return message_requester, discovery_requesters


# ── Step 3b: User IDs → company IDs ──────────────────────────────────────────


def fetch_user_companies(
    discovery_requesters: dict[str, set[str]],
) -> tuple[dict[str, str], dict[str, set[str]]]:
    """
    Resolve each unique user ID to a companyId via GET /user/{id}.

    Returns:
        user_company         {user_id: company_id}
        discovery_companies  {discovery_id: {company_id, …}}
    """
    unique_user_ids: set[str] = {uid for uids in discovery_requesters.values() for uid in uids}
    log.info("Step 3b  resolving company IDs for %d users …", len(unique_user_ids))

    user_company: dict[str, str] = {}
    for uid in unique_user_ids:
        user = _get(f"{PATH_USER}/{uid}").get("user", {})
        cid = user.get("companyId")
        if cid:
            user_company[uid] = cid
        else:
            log.debug("         user %s has no companyId", uid)

    discovery_companies: dict[str, set[str]] = {
        did: {user_company[uid] for uid in uids if uid in user_company}
        for did, uids in discovery_requesters.items()
    }

    unique_companies = {c for cs in discovery_companies.values() for c in cs}
    log.info("         %d unique companies identified", len(unique_companies))
    return user_company, discovery_companies


# ── Step 4: Company lost-revenue attribute values ─────────────────────────────


def fetch_company_revenues(
    discovery_companies: dict[str, set[str]],
) -> dict[str, float]:
    """
    Return {company_id: lost_revenue} for every unique company.
    Each company is fetched exactly once.
    """
    unique_companies: set[str] = {c for cs in discovery_companies.values() for c in cs}
    log.info("Step 4  fetching revenue for %d companies …", len(unique_companies))

    company_revenue: dict[str, float] = {}
    for cid in unique_companies:
        attrs = list(_paginate(f"{PATH_COMPANY_ATTRS}/{cid}/attribute-value", "attributeValues"))
        revenue = 0.0
        for attr in attrs:
            if attr.get("attributeId") == LOST_REVENUE_ATTR_ID:
                raw = attr.get("numericValue") or attr.get("textValue") or 0
                try:
                    revenue = float(raw)
                except (TypeError, ValueError):
                    log.warning("        non-numeric revenue for company %s: %r", cid, raw)
                break
        company_revenue[cid] = revenue

    log.info(
        "        revenue mapped for %d companies (total: %.2f)",
        len(company_revenue),
        sum(company_revenue.values()),
    )
    return company_revenue


# ── Step 5: Compare computed vs. stored totals ────────────────────────────────


def _stored_revenue(discovery: dict) -> float | None:
    """Extract the current stored revenue total from a discovery's fieldsValues."""
    for fv in discovery.get("fieldsValues") or []:
        field = fv.get("field") or {}
        if REVENUE_FIELD_ID in (field.get("id"), field.get("clientId")):
            try:
                return float(fv["value"])
            except (TypeError, ValueError, KeyError):
                return None
    return None


def compare_revenues(
    discoveries: list[dict],
    discovery_companies: dict[str, set[str]],
    company_revenue: dict[str, float],
) -> list[dict]:
    """
    For each discovery, sum its companies' revenue and compare to the stored field.
    Returns a list of diffs for discoveries where computed != stored.
    """
    log.info("Step 5  comparing revenue totals for %d discoveries …", len(discoveries))
    diffs: list[dict] = []
    for disc in discoveries:
        did = disc["id"]
        companies = discovery_companies.get(did, set())
        computed = sum(company_revenue.get(c, 0.0) for c in companies)
        stored = _stored_revenue(disc)
        stored_cmp = stored if stored is not None else 0.0
        if abs(computed - stored_cmp) > 0.01:
            diffs.append(
                {
                    "discoveryId": did,
                    "clientId": disc.get("clientId", did),
                    "title": disc.get("title", "(untitled)"),
                    "computed": computed,
                    "stored": stored,
                    "delta": computed - stored_cmp,
                    "company_count": len(companies),
                }
            )
    return diffs


# ── GraphQL client ───────────────────────────────────────────────────────────

def _graphql(operation_name: str, query: str, variables: dict) -> dict:
    """POST a single GraphQL operation; returns the 'data' key of the response."""
    _limiter.acquire()
    resp = requests.post(
        GRAPHQL_URL,
        json={"operationName": operation_name, "query": query, "variables": variables},
        headers={
            "Accept": "application/graphql-response+json,application/json;q=0.9",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {JWT_TOKEN}",
        },
        timeout=30,
    )
    resp.raise_for_status()
    body = resp.json()
    if body.get("errors"):
        raise RuntimeError(f"GraphQL {operation_name} errors: {body['errors']}")
    return body.get("data", {})


_GQL_QUERY_SCORES = """
query getDiscoveryScores($id: ID!) {
  discovery(id: $id) {
    discoveryScores {
      id
      discoveryfield { id }
    }
  }
}
"""

_GQL_MUTATION_UPDATE_SCORE = """
mutation updateDiscoveryScore($discovery_id: ID!, $data: DiscoveryUpdateInput!) {
  updateDiscovery(id: $discovery_id, data: $data) {
    id
    updatedAt
    discoveryScores {
      id
      numValue
      discoveryfield { id }
    }
  }
}
"""


# ── Step 6a: Resolve score record IDs ────────────────────────────────────────


def fetch_score_ids(diffs: list[dict]) -> dict[str, str]:
    """
    For each discovery in the diff list, find the DiscoveryScore record ID
    that corresponds to REVENUE_FIELD_ID.

    Returns {discovery_client_id: score_record_id}.
    """
    log.info("Step 6a  fetching score record IDs for %d discoveries …", len(diffs))
    score_ids: dict[str, str] = {}
    for d in diffs:
        cid = d["clientId"]
        data = _graphql("getDiscoveryScores", _GQL_QUERY_SCORES, {"id": cid})
        scores = (data.get("discovery") or {}).get("discoveryScores", [])
        for score in scores:
            if (score.get("discoveryfield") or {}).get("id") == REVENUE_FIELD_ID:
                score_ids[cid] = score["id"]
                break
        if cid not in score_ids:
            log.warning("         no score record found for discovery %s field %s", cid, REVENUE_FIELD_ID)
    log.info("         %d score record IDs resolved", len(score_ids))
    return score_ids


# ── Step 6b: Write updated revenue totals ────────────────────────────────────


def update_discovery_revenues(diffs: list[dict], score_ids: dict[str, str]) -> None:
    """
    Write updated revenue totals via updateDiscoveryScore.
    Uses 'update' when a DiscoveryScore record already exists, 'create' otherwise.
    """
    if DRY_RUN:
        log.info(
            "Step 6b  DRY RUN — %d updates suppressed (set HARVESTR_DRY_RUN=0 to apply)",
            len(diffs),
        )
        for d in diffs:
            action = "update" if d["clientId"] in score_ids else "create"
            log.info(
                "         would %s %s (%s)  %s → %d",
                action, d["clientId"], d["title"],
                f"{d['stored']:.0f}" if d["stored"] is not None else "(unset)",
                d["computed"],
            )
        return

    log.info("Step 6b  writing revenue updates for %d discoveries …", len(diffs))
    for d in diffs:
        cid = d["clientId"]
        score_id = score_ids.get(cid)
        if score_id:
            scores_payload = {
                "update": [{"data": {"numValue": d["computed"]}, "where": {"id": score_id}}]
            }
            action = "updated"
        else:
            scores_payload = {
                "create": [{
                    "numValue": d["computed"],
                    "discoveryfield": {"connect": {"id": REVENUE_FIELD_ID}},
                }]
            }
            action = "created"
        _graphql(
            "updateDiscoveryScore",
            _GQL_MUTATION_UPDATE_SCORE,
            {"discovery_id": cid, "data": {"discoveryScores": scores_payload}},
        )
        log.info("         %s %-24s %+12.0f  %s", action, cid, d["delta"], d["title"])


# ── Output ────────────────────────────────────────────────────────────────────

_HARVESTR_DISCOVERY_URL = "https://app.harvestr.io/components/0/list/{}"
_LINK_COL_WIDTH = 24


def _hyperlink(url: str, text: str) -> str:
    """Wrap text in an OSC 8 terminal hyperlink (clickable in iTerm2/modern terminals)."""
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"


def _linked_id(client_id: str) -> str:
    """Return a terminal hyperlink padded to _LINK_COL_WIDTH visible characters."""
    url = _HARVESTR_DISCOVERY_URL.format(client_id)
    link = _hyperlink(url, client_id)
    # OSC escape bytes are invisible, so pad based on visible text length only
    padding = max(0, _LINK_COL_WIDTH - len(client_id))
    return link + " " * padding


def _print_report(diffs: list[dict]) -> None:
    if not diffs:
        print("\nNo revenue discrepancies found — all totals are current.\n")
        return

    w = 80
    print(f"\n{'─' * w}")
    print(f"  Revenue mismatches found: {len(diffs)}")
    print(f"{'─' * w}")
    print(f"  {'Discovery':<{_LINK_COL_WIDTH}}  {'Computed':>12}  {'Stored':>12}  {'Delta':>12}  Title")
    print(f"{'─' * w}")
    for d in sorted(diffs, key=lambda x: abs(x["delta"]), reverse=True):
        stored_s = (
            f"{d['stored']:>12.0f}" if d["stored"] is not None else f"{'(unset)':>12}"
        )
        print(
            f"  {_linked_id(d['clientId'])}  {d['computed']:>12.0f}"
            f"  {stored_s}  {d['delta']:>+12.0f}  {d['title']}"
        )
    print(f"{'─' * w}\n")


# ── Entry point ───────────────────────────────────────────────────────────────


def run() -> None:
    if not API_TOKEN:
        log.error("HARVESTR_API_TOKEN environment variable is not set.")
        sys.exit(1)

    discoveries = fetch_discoveries()
    discovery_feedback = fetch_feedback(discoveries)
    _, discovery_requesters = fetch_requesters(discovery_feedback)
    _, discovery_companies = fetch_user_companies(discovery_requesters)
    company_revenue = fetch_company_revenues(discovery_companies)
    diffs = compare_revenues(discoveries, discovery_companies, company_revenue)
    _print_report(diffs)

    if diffs:
        if not JWT_TOKEN:
            log.warning("HARVESTR_JWT_TOKEN not set — skipping revenue field updates.")
            return
        score_ids = fetch_score_ids(diffs)
        update_discovery_revenues(diffs, score_ids)


if __name__ == "__main__":
    run()
