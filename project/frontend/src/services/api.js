const API_BASE = ''; // Proxied via Vite config to http://127.0.0.1:8000

export async function getSettings() {
  const res = await fetch(`${API_BASE}/api/settings`);
  if (!res.ok) throw new Error('Failed to fetch settings');
  return res.json();
}

export async function updateSettings(settings) {
  const res = await fetch(`${API_BASE}/api/settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  });
  if (!res.ok) throw new Error('Failed to update settings');
  return res.json();
}

export async function uploadFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  
  const res = await fetch(`${API_BASE}/api/upload`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to upload file');
  }
  return res.json();
}

export async function startOffline(fileId, extension) {
  const formData = new FormData();
  formData.append('file_id', fileId);
  formData.append('extension', extension);
  
  const res = await fetch(`${API_BASE}/api/start-offline`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to run offline detection');
  }
  return res.json();
}

export async function startOnline({ option, interfaceVal, ipFilter, portFilter, interfaceName, pcapFile }) {
  const formData = new FormData();
  formData.append('option', option);
  if (interfaceVal) formData.append('interface', interfaceVal);
  if (ipFilter) formData.append('ip_filter', ipFilter);
  if (portFilter) formData.append('port_filter', portFilter);
  if (interfaceName) formData.append('interface_name', interfaceName);
  if (pcapFile) formData.append('pcap_file', pcapFile);
  
  const res = await fetch(`${API_BASE}/api/start-online`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) throw new Error('Failed to start online detection');
  return res.json();
}

export async function stopOnline() {
  const res = await fetch(`${API_BASE}/api/stop-online`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to stop online detection');
  return res.json();
}

export async function getOnlineStatus() {
  const res = await fetch(`${API_BASE}/api/online/status`);
  if (!res.ok) throw new Error('Failed to fetch online status');
  return res.json();
}

export async function getDashboardData() {
  const res = await fetch(`${API_BASE}/api/dashboard`);
  if (!res.ok) throw new Error('Failed to fetch dashboard data');
  return res.json();
}

export async function getModelHealth() {
  const res = await fetch(`${API_BASE}/api/metrics`);
  if (!res.ok) throw new Error('Failed to fetch model health');
  return res.json();
}

export async function getHistory({ search, mode, prediction, protocol, limit = 25, offset = 0, sortBy = 'timestamp', sortOrder = 'DESC' } = {}) {
  const params = new URLSearchParams({
    limit: limit.toString(),
    offset: offset.toString(),
    sort_by: sortBy,
    sort_order: sortOrder
  });
  
  if (search) params.append('search', search);
  if (mode) params.append('mode', mode);
  if (prediction !== undefined && prediction !== '') params.append('prediction', prediction.toString());
  if (protocol) params.append('protocol', protocol);
  
  const res = await fetch(`${API_BASE}/api/history?${params.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch history');
  return res.json();
}

export async function getShapExplanation(historyId) {
  const res = await fetch(`${API_BASE}/api/shap/${historyId}`);
  if (!res.ok) throw new Error('Failed to fetch SHAP explanation');
  return res.json();
}

export async function getLogs(limit = 50) {
  const res = await fetch(`${API_BASE}/api/logs?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch system logs');
  return res.json();
}

export async function getLatestPrediction() {
  const res = await fetch(`${API_BASE}/api/prediction`);
  if (!res.ok) throw new Error('Failed to fetch latest prediction');
  return res.json();
}

export async function getLastRun() {
  const res = await fetch(`${API_BASE}/api/last-run`);
  if (!res.ok) throw new Error('Failed to fetch last run');
  return res.json();
}

export async function getInterfaces() {
  const res = await fetch(`${API_BASE}/api/interfaces`);
  if (!res.ok) throw new Error('Failed to fetch network interfaces');
  return res.json();
}

export async function getHistoryStats(mode) {
  const url = mode ? `${API_BASE}/api/history/stats?mode=${encodeURIComponent(mode)}` : `${API_BASE}/api/history/stats`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch history stats');
  return res.json();
}

export function getExportUrl(type = 'json', { mode, search, prediction, protocol } = {}) {
  const params = new URLSearchParams();
  if (mode) params.append('mode', mode);
  if (search) params.append('search', search);
  if (prediction !== undefined && prediction !== '') params.append('prediction', prediction.toString());
  if (protocol) params.append('protocol', protocol);
  
  let endpoint = '/api/export-csv';
  if (type === 'json') endpoint = '/api/export-json';
  else if (type === 'pdf') endpoint = '/api/download-pdf';
  else if (type === 'xml') endpoint = '/api/export-xml';
  else if (type === 'txt') endpoint = '/api/export-txt';
  
  const query = params.toString();
  return `${API_BASE}${endpoint}${query ? `?${query}` : ''}`;
}


