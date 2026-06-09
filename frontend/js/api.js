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
  unlock: (packetId, otp) => post('/unlock', { packetId, otp }),
  checkPacket: (packetId) => get(`/status/${encodeURIComponent(packetId)}`),
  status: (packetId) => get(`/status/${encodeURIComponent(packetId)}`),
  registerTotp: (packetId, mobileNumber, userId) => post('/register-totp', { packetId, mobileNumber, userId }),
  unlockTotp: (packetId, userId, totp) => post('/unlock-totp', { packetId, userId, totp }),
  customerSignup: (mobileNumber, password) => post('/customer-signup', { mobileNumber, password }),
  customerLogin: (mobileNumber, password) => post('/customer-login', { mobileNumber, password }),
  pairTotp: (packetId, code) => post('/' + encodeURIComponent(packetId) + '/totp/pair', { code }),
  getTotpCurrent: async (packetId) => {
    const res = await fetch(`/api/totp/current?packetId=${encodeURIComponent(packetId)}`);
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
  },
  getTotpSetup: async (packetId) => {
    const res = await fetch(`/api/packet/${encodeURIComponent(packetId)}/totp/setup`);
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
};
