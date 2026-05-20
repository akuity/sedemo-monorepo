# Harvestr Data Jobs

## What

Python jobs that augment Harvest Data for our needs.


## Lost Revenue Job

Scans all open discoveries, traces feedback → messages → requesters → companies, sums each company's Lost Revenue attribute, and compares the total to the stored value on the discovery. Discoveries with a mismatch are reported and optionally updated.

### Setup

```bash
pip install requests
```

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `HARVESTR_API_TOKEN` | Yes | Private app token from Harvestr Settings |
| `HARVESTR_JWT_TOKEN` | To write | Bearer JWT from an active browser session (DevTools → Network → any `graphql.harvestr.io` request → Authorization header) |
| `HARVESTR_DRY_RUN` | No | Set to `0` to write updates; defaults to `1` (report only) |
| `HARVESTR_DEBUG_DIR` | No | Directory to cache raw API responses for debugging (e.g. `./debug`) |

### Usage

```bash
# Report discrepancies only
HARVESTR_API_TOKEN=<token> python main.py

# Report and write updates
HARVESTR_API_TOKEN=<token> HARVESTR_JWT_TOKEN=<jwt> HARVESTR_DRY_RUN=0 python main.py

# Use cached responses (faster re-runs during debugging)
HARVESTR_API_TOKEN=<token> HARVESTR_DEBUG_DIR=./debug python main.py
```


