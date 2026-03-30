# decoda-threat-lab

Staging-only threat simulation server for validating Decoda detection pipelines safely.

## What this repo provides

- Small web UI to trigger scenarios.
- Backend endpoints:
  - `POST /run-scenario`
  - `GET /history`
  - `GET /health`
- Structured JSON logs for every run.
- Two modes:
  - **synthetic**: generates clearly marked simulation ingestion payloads.
  - **testnet**: performs benign suspicious-looking helper actions using throwaway testnet targets only.

## Setup

1. Use Node.js 18+.
2. Copy env template and edit values:

```bash
cp .env.example .env
```

3. Export env vars and run server:

```bash
set -a; source .env; set +a
npm start
```

4. Open http://localhost:3000

## Safety guards (hard requirements)

Threat runs are blocked unless all checks pass:

- `ENABLE_THREAT_LAB=true`
- `DECUDA_BASE_URL` hostname must match `APPROVED_STAGING_DOMAINS`
- production-like hostnames are refused (`prod`, `production`, `api.decoda.com`, `app.decoda.com`)
- testnet RPC must not look like mainnet RPC
- wallet lists are refused unless wallets are in `LAB_TARGET_WALLETS` or explicitly marked as `{ address, lab_target: true }`

## Connecting to Decoda staging

`DECUDA_BASE_URL` should point to your staging Decoda API host. In **synthetic** mode, the service prepares a clearly-labeled payload intended for a staging simulation/ingestion path:

- endpoint shape: `${DECUDA_BASE_URL}/simulation/ingest`
- metadata always included:
  - `source=threat-lab`
  - `simulation=true`
  - `scenario=<scenario>`
  - `simulation_id=<uuid>`
  - `is_live_data=false` (synthetic mode)

## Scenario list

- `unlimited_approval`
- `large_native_transfer`
- `admin_privilege_abuse`
- `flash_loan_like`
- `oracle_anomaly`

## Synthetic vs testnet proof

- **Synthetic mode proves**:
  - Decoda can ingest intentionally labeled simulation events.
  - alerting/incidents/audit updates are wired end-to-end on staged synthetic signals.
- **Testnet mode proves**:
  - Decoda reacts correctly to benign on-chain-like activity patterns from throwaway assets.
  - helper actions can model suspicious patterns without touching production or mainnet.

## Testnet helpers (optional)

When `TESTNET_HELPERS_ENABLED=true`, testnet mode can emit helper action metadata for:

- large transfer between throwaway wallets
- unlimited approval on a test token
- dummy admin-style function call on a lab contract

These helpers are intentionally benign and bounded to test assets.
