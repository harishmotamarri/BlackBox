const BASE = '/api/packet';

async function post(endpoint, body) {
  const res = await fetch(`${BASE}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  // Read as text first to avoid JSON crashes on HTML/server errors
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error('Invalid server response');
  }

  if (!res.ok) {
    throw new Error(data.error || 'Server error');
  }

  return data;
}

async function get(endpoint) {
  const res = await fetch(`${BASE}${endpoint}`);
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error('Invalid server response');
  }
  if (!res.ok) {
    throw new Error(data.error || 'Server error');
  }
  return data;
}

export const api = {
  requestOtp: (packetId) => post('/request-otp', { packetId }),
  verifyOtp: (packetId, otp) => post('/verify-otp', { packetId, otp }),
  unlock: (packetId) => post('/unlock', { packetId }),
  status: (packetId) => get(`/status/${encodeURIComponent(packetId)}`)
};
