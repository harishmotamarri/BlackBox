const BASE = '/api/packet';

async function post(endpoint, body) {
  const res = await fetch(`${BASE}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

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
  verifyCode: (packetId, verificationCode) => post('/verify-code', { packetId, verificationCode }),
  unlock: (packetId) => post('/unlock', { packetId }),
  checkPacket: (packetId) => get(`/status/${encodeURIComponent(packetId)}`),
  status: (packetId) => get(`/status/${encodeURIComponent(packetId)}`)
};
