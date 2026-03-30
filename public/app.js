const els = {
  baseUrl: document.getElementById('baseUrl'),
  workspace: document.getElementById('workspace'),
  target: document.getElementById('target'),
  scenario: document.getElementById('scenario'),
  mode: document.getElementById('mode'),
  runBtn: document.getElementById('runBtn'),
  result: document.getElementById('result'),
  history: document.getElementById('history'),
  refreshBtn: document.getElementById('refreshBtn')
};

document.querySelectorAll('[data-scenario]').forEach((btn) => {
  btn.addEventListener('click', () => {
    els.scenario.value = btn.dataset.scenario;
  });
});

function renderResult(data) {
  const view = {
    status: data.status,
    simulation_id: data.simulation_id,
    timestamp: data.timestamp,
    expected_decoda_reaction: data.expected_decoda_reaction,
    execution: data.execution
  };
  els.result.textContent = JSON.stringify(view, null, 2);
}

async function runScenario() {
  const payload = {
    staging_api_url: els.baseUrl.value.trim(),
    workspace: els.workspace.value.trim(),
    target: els.target.value.trim(),
    scenario: els.scenario.value,
    mode: els.mode.value
  };

  const res = await fetch('/run-scenario', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  const data = await res.json();
  if (!res.ok) {
    els.result.textContent = `Error: ${data.error}`;
    return;
  }

  renderResult(data);
  await loadHistory();
}

async function loadHistory() {
  const res = await fetch('/history');
  const data = await res.json();
  els.history.textContent = JSON.stringify(data.runs, null, 2);
}

els.runBtn.addEventListener('click', () => {
  runScenario().catch((err) => {
    els.result.textContent = `Error: ${err.message}`;
  });
});

els.refreshBtn.addEventListener('click', () => {
  loadHistory().catch((err) => {
    els.history.textContent = `Error: ${err.message}`;
  });
});

loadHistory().catch(() => {
  els.history.textContent = 'Unable to load history.';
});
