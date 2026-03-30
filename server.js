const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const ENABLE_THREAT_LAB = process.env.ENABLE_THREAT_LAB === 'true';
const DECUDA_BASE_URL = process.env.DECUDA_BASE_URL || '';
const APPROVED_STAGING_DOMAINS = (process.env.APPROVED_STAGING_DOMAINS || 'staging.decoda.ai,api.staging.decoda.ai,staging.decoda.internal')
  .split(',')
  .map((x) => x.trim().toLowerCase())
  .filter(Boolean);
const TESTNET_RPC_URL = process.env.TESTNET_RPC_URL || '';
const TESTNET_HELPERS_ENABLED = process.env.TESTNET_HELPERS_ENABLED === 'true';
const LAB_TARGET_WALLETS = new Set(
  (process.env.LAB_TARGET_WALLETS || '')
    .split(',')
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean)
);

const scenarios = {
  unlimited_approval: 'Decoda should flag unusual allowance escalation and create/update an approval-risk incident.',
  large_native_transfer: 'Decoda should detect anomalous transfer volume and produce a high-severity transfer alert.',
  admin_privilege_abuse: 'Decoda should detect suspicious privileged function behavior and update audit trail context.',
  flash_loan_like: 'Decoda should flag rapid in/out liquidity-like behavior and correlate it into one incident.',
  oracle_anomaly: 'Decoda should detect abnormal oracle-style value movement and annotate risk timeline.'
};

const runs = [];

function jsonResponse(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
  });
  res.end(JSON.stringify(payload));
}

function logStructured(event, details) {
  const message = {
    level: 'info',
    ts: new Date().toISOString(),
    event,
    ...details
  };
  console.log(JSON.stringify(message));
}

function isApprovedStagingUrl(baseUrl) {
  try {
    const parsed = new URL(baseUrl);
    const hostname = parsed.hostname.toLowerCase();
    const approved = APPROVED_STAGING_DOMAINS.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
    const prodDeniedPatterns = ['prod', 'production', 'api.decoda.com', 'app.decoda.com'];
    const explicitProdMatch = prodDeniedPatterns.some((pattern) => hostname.includes(pattern));
    return approved && !explicitProdMatch;
  } catch {
    return false;
  }
}

function isMainnetRpc(urlText) {
  if (!urlText) return false;
  const lowered = urlText.toLowerCase();
  const mainnetPatterns = [
    'mainnet',
    'eth.llamarpc.com',
    'rpc.ankr.com/eth',
    'polygon-rpc.com',
    'bsc-dataseed',
    'arb1.arbitrum.io'
  ];
  return mainnetPatterns.some((pattern) => lowered.includes(pattern));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1_000_000) {
        reject(new Error('payload_too_large'));
      }
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('invalid_json'));
      }
    });
  });
}

function staticFile(res, fileName, contentType) {
  const filePath = path.join(__dirname, 'public', fileName);
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(content);
  });
}

function validateWallets(wallets) {
  if (!wallets || wallets.length === 0) return { ok: true };
  for (const wallet of wallets) {
    if (typeof wallet === 'string') {
      if (!LAB_TARGET_WALLETS.has(wallet.toLowerCase())) {
        return { ok: false, reason: `unknown wallet ${wallet}. Add it to LAB_TARGET_WALLETS or mark explicit lab_target.` };
      }
      continue;
    }

    if (wallet && typeof wallet === 'object' && typeof wallet.address === 'string' && wallet.lab_target === true) {
      continue;
    }

    return { ok: false, reason: 'wallet entries must be strings in LAB_TARGET_WALLETS or objects with {address, lab_target:true}.' };
  }

  return { ok: true };
}

function runSynthetic(metadata, input) {
  return {
    status: 'queued',
    dispatch: {
      method: 'POST',
      endpoint: `${DECUDA_BASE_URL.replace(/\/$/, '')}/simulation/ingest`,
      body: {
        ...metadata,
        workspace: input.workspace,
        target: input.target,
        mode: 'synthetic',
        decoda_label: 'synthetic-threat-lab-event'
      }
    },
    note: 'Synthetic mode prepares clearly labeled ingestion payloads for Decoda staging.'
  };
}

function runTestnet(metadata, input) {
  const helperOutput = [];

  if (TESTNET_HELPERS_ENABLED) {
    if (isMainnetRpc(TESTNET_RPC_URL)) {
      throw new Error('Configured TESTNET_RPC_URL appears to be mainnet and was blocked.');
    }

    if (input.scenario === 'large_native_transfer') {
      helperOutput.push({ action: 'large_transfer', tx: `0xtestnet-${metadata.simulation_id.slice(0, 12)}`, amount: '0.42 TEST' });
    }

    if (input.scenario === 'unlimited_approval') {
      helperOutput.push({ action: 'unlimited_approval', tx: `0xtestnet-${metadata.simulation_id.slice(12, 24)}`, allowance: 'MAX_UINT256' });
    }

    if (input.scenario === 'admin_privilege_abuse') {
      helperOutput.push({ action: 'dummy_admin_call', tx: `0xtestnet-${metadata.simulation_id.slice(24, 36)}`, function: 'setRiskFlag(uint8)' });
    }
  }

  return {
    status: 'completed',
    rpc: TESTNET_RPC_URL || 'not-configured',
    helper_actions: helperOutput,
    note: 'Testnet mode generated benign suspicious-looking activity only for throwaway/lab targets.'
  };
}

function handleRunScenario(req, res) {
  parseBody(req)
    .then((body) => {
      if (!ENABLE_THREAT_LAB) {
        return jsonResponse(res, 403, { error: 'ENABLE_THREAT_LAB must be true.' });
      }

      if (!isApprovedStagingUrl(DECUDA_BASE_URL)) {
        return jsonResponse(res, 403, { error: 'DECUDA_BASE_URL must be an approved staging domain and never production.' });
      }

      if (body.staging_api_url && body.staging_api_url !== DECUDA_BASE_URL) {
        return jsonResponse(res, 400, { error: 'staging_api_url must match configured DECUDA_BASE_URL.' });
      }

      if (isMainnetRpc(TESTNET_RPC_URL)) {
        return jsonResponse(res, 403, { error: 'Mainnet RPC endpoints are blocked.' });
      }

      const scenario = body.scenario;
      const mode = body.mode;

      if (!scenarios[scenario]) {
        return jsonResponse(res, 400, { error: 'Unknown scenario.' });
      }

      if (mode !== 'synthetic' && mode !== 'testnet') {
        return jsonResponse(res, 400, { error: 'Mode must be synthetic or testnet.' });
      }

      const walletValidation = validateWallets(body.wallets);
      if (!walletValidation.ok) {
        return jsonResponse(res, 400, { error: walletValidation.reason });
      }

      const simulationId = crypto.randomUUID();
      const timestamp = new Date().toISOString();
      const metadata = {
        source: 'threat-lab',
        simulation: true,
        scenario,
        simulation_id: simulationId,
        is_live_data: mode === 'synthetic' ? false : undefined
      };

      let execution;
      if (mode === 'synthetic') {
        execution = runSynthetic(metadata, body);
      } else {
        execution = runTestnet(metadata, body);
      }

      const record = {
        status: 'ok',
        simulation_id: simulationId,
        timestamp,
        expected_decoda_reaction: scenarios[scenario],
        request: {
          ...metadata,
          mode,
          workspace: body.workspace,
          target: body.target
        },
        execution
      };

      runs.unshift(record);
      if (runs.length > 100) runs.pop();

      logStructured('scenario_run', {
        simulation_id: simulationId,
        mode,
        scenario,
        workspace: body.workspace,
        target: body.target,
        source: 'threat-lab',
        simulation: true,
        is_live_data: mode === 'synthetic' ? false : null
      });

      return jsonResponse(res, 200, record);
    })
    .catch((error) => {
      const status = error.message === 'payload_too_large' ? 413 : 400;
      jsonResponse(res, status, { error: error.message });
    });
}

const server = http.createServer((req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
    });
    res.end();
    return;
  }

  if (req.url === '/' && req.method === 'GET') {
    return staticFile(res, 'index.html', 'text/html; charset=utf-8');
  }

  if (req.url === '/app.js' && req.method === 'GET') {
    return staticFile(res, 'app.js', 'application/javascript; charset=utf-8');
  }

  if (req.url === '/styles.css' && req.method === 'GET') {
    return staticFile(res, 'styles.css', 'text/css; charset=utf-8');
  }

  if (req.url === '/health' && req.method === 'GET') {
    return jsonResponse(res, 200, {
      ok: true,
      service: 'decoda-threat-lab',
      time: new Date().toISOString(),
      enabled: ENABLE_THREAT_LAB,
      staging_url_valid: isApprovedStagingUrl(DECUDA_BASE_URL),
      rpc_blocked: isMainnetRpc(TESTNET_RPC_URL)
    });
  }

  if (req.url === '/history' && req.method === 'GET') {
    return jsonResponse(res, 200, { runs });
  }

  if (req.url === '/run-scenario' && req.method === 'POST') {
    return handleRunScenario(req, res);
  }

  jsonResponse(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  logStructured('server_started', {
    port: PORT,
    enable_threat_lab: ENABLE_THREAT_LAB,
    staging_url: DECUDA_BASE_URL,
    approved_staging_domains: APPROVED_STAGING_DOMAINS
  });
});
