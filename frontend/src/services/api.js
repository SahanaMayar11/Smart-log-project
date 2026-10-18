// API service for communicating with Python Flask backend with Token Authentication

const API_BASE = '/api';

function getAuthHeaders() {
  const token = localStorage.getItem('smartlog_token');
  const headers = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

async function handleResponse(res) {
  if (res.status === 401) {
    localStorage.removeItem('smartlog_token');
    if (window.location.pathname !== '/login' && window.location.pathname !== '/') {
      window.location.href = '/login';
    }
  }

  const text = await res.text().catch(() => '');
  if (!text || !text.trim()) {
    if (!res.ok) {
      return {
        status: 'error',
        success: false,
        error: `Server returned error status (${res.status})`,
        message: `Server returned error status (${res.status})`
      };
    }
    return { status: 'success', success: true };
  }

  try {
    const data = JSON.parse(text);
    if (!res.ok && data && typeof data === 'object') {
      if (!data.error && !data.message) {
        data.error = `Server error (${res.status})`;
        data.message = data.error;
      }
      data.success = false;
    }
    return data;
  } catch (err) {
    console.error('Failed to parse response JSON:', err, text);
    return {
      status: 'error',
      success: false,
      error: `Invalid JSON from server (${res.status})`,
      message: `Invalid server response (${res.status}): ${text.substring(0, 100)}`
    };
  }
}

export async function loginAdmin(username, password) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  const data = await res.json();
  if (res.ok && data.token) {
    localStorage.setItem('smartlog_token', data.token);
  }
  return data;
}

export async function analyzeSystemLogs(hours = 24, maxEvents = 5000) {
  const res = await fetch(`${API_BASE}/system-logs/analyze`, {
    method: 'POST',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ hours, max_events: maxEvents })
  });
  return handleResponse(res);
}



export async function fetchDashboardStats() {
  const res = await fetch(`${API_BASE}/dashboard/stats`, {
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

export async function fetchParsedLogs(search = '', level = '', severity = '') {
  const params = new URLSearchParams({ search, level, severity });
  const res = await fetch(`${API_BASE}/logs/parsed?${params.toString()}`, {
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

export async function fetchExtractedFeatures() {
  const res = await fetch(`${API_BASE}/features`, {
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

export async function fetchDetectionResults(fileId = null) {
  const url = fileId ? `${API_BASE}/detection/results?file_id=${fileId}` : `${API_BASE}/detection/results`;
  const res = await fetch(url, {
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

export async function fetchAttackScenarios() {
  const res = await fetch(`${API_BASE}/test/scenarios`, {
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

export async function injectAttackScenario(scenario) {
  const res = await fetch(`${API_BASE}/test/inject-anomaly`, {
    method: 'POST',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario })
  });
  return handleResponse(res);
}

export async function pasteAndAnalyzeLog(logContent) {
  const res = await fetch(`${API_BASE}/logs/paste-analyze`, {
    method: 'POST',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ log_content: logContent })
  });
  return handleResponse(res);
}

export async function fetchShapExplanations() {
  const res = await fetch(`${API_BASE}/shap/explanations`, {
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

export async function fetchReportSummary() {
  const res = await fetch(`${API_BASE}/reports/summary`, {
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

export async function fetchLiveSystemLogs(limit = 100) {
  const res = await fetch(`${API_BASE}/system-logs/live?limit=${limit}`, {
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

export async function startLiveMonitoring(interval = 3.0) {
  const res = await fetch(`${API_BASE}/system-logs/monitor/start`, {
    method: 'POST',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ interval })
  });
  return handleResponse(res);
}

export async function stopLiveMonitoring() {
  const res = await fetch(`${API_BASE}/system-logs/monitor/stop`, {
    method: 'POST',
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

export async function fetchMonitoringStatus() {
  const res = await fetch(`${API_BASE}/system-logs/monitor/status`, {
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

export async function injectSyntheticAnomaly(payload = {}) {
  const res = await fetch(`${API_BASE}/test/inject-anomaly`, {
    method: 'POST',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  return handleResponse(res);
}

export async function cleanTestData() {
  const res = await fetch(`${API_BASE}/test/cleanup`, {
    method: 'POST',
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

export async function deleteInjectedEvents() {
  const res = await fetch(`${API_BASE}/test/injected-events`, {
    method: 'DELETE',
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

export async function fetchTestHistory() {
  const res = await fetch(`${API_BASE}/test/history`, {
    headers: getAuthHeaders()
  });
  return handleResponse(res);
}

