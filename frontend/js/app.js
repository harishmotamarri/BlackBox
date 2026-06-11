import { api } from './api.js';
import { $, setStatus, clearStatus, renderDefaultView, renderUnlockedView, renderVerificationView, renderTamperedView } from './ui.js';

// --- Client-side TOTP Calculation using Web Cryptography API ---
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(str) {
  str = str.toUpperCase().replace(/=+$/, '');
  let bits = '';
  for (let i = 0; i < str.length; i++) {
    const val = BASE32_ALPHABET.indexOf(str[i]);
    if (val === -1) throw new Error(`Invalid base32 character: ${str[i]}`);
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

async function generateBrowserTOTP(secret) {
  const windowSeconds = 60;
  const timeStep = Math.floor(Date.now() / (windowSeconds * 1000));
  
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(0, 0); // High 32 bits
  view.setUint32(4, timeStep); // Low 32 bits

  const keyBytes = base32Decode(secret);
  const cryptoKey = await window.crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );

  const signature = await window.crypto.subtle.sign("HMAC", cryptoKey, buffer);
  const hmacResult = new Uint8Array(signature);

  const offset = hmacResult[hmacResult.length - 1] & 0x0f;
  const code = (
    ((hmacResult[offset] & 0x7f) << 24) |
    ((hmacResult[offset + 1] & 0xff) << 16) |
    ((hmacResult[offset + 2] & 0xff) << 8) |
    (hmacResult[offset + 3] & 0xff)
  ) % 1000000;

  return String(code).padStart(6, '0');
}

// --- Customer Portal Variables & Session ---
let customerMobile = null;
let customerOrders = [];
let portalTimerInterval = null;
let remainingSeconds = 30;
let isFetchingTotp = false;
let currentPairingPacketId = null;

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function setTotpStatus(message, type = 'info') {
  const el = $('totp-status');
  if (!el) return;
  el.innerHTML = message;
  el.dataset.type = type;
}

function clearTotpStatus() {
  const el = $('totp-status');
  if (!el) return;
  el.innerHTML = '';
  delete el.dataset.type;
}

async function syncTotpFromServer() {
  if (isFetchingTotp) return;
  isFetchingTotp = true;
  try {
    if (customerOrders.length === 0) return;

    // Fetch TOTPs for all packets concurrently
    const promises = customerOrders.map(async (order) => {
      try {
        const data = await api.getTotpCurrent(order.packetId);
        if (data.paired) {
          order.otp = data.otp;
          order.paired = true;
        } else {
          order.otp = 'Not Paired';
          order.paired = false;
        }
        return data.remainingSeconds;
      } catch (err) {
        console.error(`Failed to sync TOTP for packet ${order.packetId}:`, err);
        order.otp = 'Not Paired';
        order.paired = false;
        return 30;
      }
    });

    const results = await Promise.all(promises);
    if (results.length > 0) {
      remainingSeconds = results[0];
    }
    updateListDisplay();
  } catch (err) {
    console.error('Failed to sync TOTP from server:', err);
  } finally {
    isFetchingTotp = false;
  }
}

function updateListDisplay() {
  if (customerOrders.length === 0) return;

  customerOrders.forEach((order, idx) => {
    const isCodePaired = order.paired;
    let formattedCode = '--- ---';
    
    if (isCodePaired && order.otp && order.otp !== 'Not Paired' && order.otp !== 'Error') {
      formattedCode = `${order.otp.slice(0, 3)} ${order.otp.slice(3)}`;
    } else if (order.otp === 'Not Paired') {
      formattedCode = 'Not Paired';
    } else {
      formattedCode = 'Loading...';
    }

    const codeEl = $(`totpCode-${idx}`);
    if (codeEl) {
      codeEl.innerText = formattedCode;
      if (!isCodePaired) {
        codeEl.classList.add('unpaired');
      } else {
        codeEl.classList.remove('unpaired');
      }
    }

    const timerContainer = $(`totpTimerContainer-${idx}`);
    if (timerContainer) {
      if (isCodePaired) {
        timerContainer.classList.remove('hidden');
      } else {
        timerContainer.classList.add('hidden');
      }
    }

    const circleFill = $(`totpCircleFill-${idx}`);
    if (circleFill) {
      // Circumference of R=12 circle is 2 * Math.PI * 12 = 75.398
      const circumference = 75.4;
      const pct = remainingSeconds / 30;
      const offset = (1 - pct) * circumference;
      circleFill.style.strokeDashoffset = offset;

      if (remainingSeconds <= 5) {
        circleFill.classList.add('warning');
      } else {
        circleFill.classList.remove('warning');
      }
    }

    const timerText = $(`totpTimerText-${idx}`);
    if (timerText) {
      timerText.innerText = `${remainingSeconds}s`;
      if (remainingSeconds <= 5) {
        timerText.style.color = '#ef4444';
      } else {
        timerText.style.color = 'var(--muted)';
      }
    }
  });
}

// --- Countdown Loop ---
function startPortalTimer() {
  if (portalTimerInterval) {
    updateListDisplay();
    return;
  }

  async function update() {
    if (customerOrders.length === 0) return;
    
    remainingSeconds--;

    if (remainingSeconds <= 0) {
      await syncTotpFromServer();
    } else {
      updateListDisplay();
    }
  }

  syncTotpFromServer().then(() => {
    if (!portalTimerInterval) {
      portalTimerInterval = setInterval(update, 1000);
    }
  });
}

// --- Render Scrollable TOTP List ---
function renderCarousel() {
  const container = $('totp-list-container');
  if (!container) return;

  if (customerOrders.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; color: var(--muted); padding: 30px 0;">
        <p style="margin: 0; font-size: 0.95rem;">No active orders found.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = customerOrders.map((order, idx) => {
    const isCodePaired = order.paired;
    
    // Status badge classes
    let statusClass = 'status-badge-locked';
    if (order.status === 'UNLOCKED') statusClass = 'status-badge-unlocked';
    if (order.status === 'TAMPERED') statusClass = 'status-badge-tampered';
    if (order.status === 'VERIFIED') statusClass = 'status-badge-verified';

    // Route info
    const routeInfo = (order.fromLocation && order.toLocation && order.fromLocation !== '-' && order.toLocation !== '-')
      ? `${escapeHtml(order.fromLocation)} → ${escapeHtml(order.toLocation)}`
      : 'In Warehouse';

    return `
      <div class="totp-item-card" data-index="${idx}">
        <div class="totp-item-header">
          <div class="totp-item-meta">
            <span class="totp-item-packet-id">Packet: ${escapeHtml(order.packetId)}</span>
            <span class="totp-item-route">${routeInfo}</span>
          </div>
          <span class="status-badge ${statusClass}">${escapeHtml(order.status)}</span>
        </div>
        <div class="totp-item-body">
          <div class="totp-item-code-container">
            <div class="totp-code totp-item-code" id="totpCode-${idx}" style="margin-bottom: 0;">Loading...</div>
          </div>
          <div class="totp-timer-container" id="totpTimerContainer-${idx}">
            ${!isCodePaired ? `
              <button class="btn btn-primary" onclick="window.showTotpSetup('${escapeHtml(order.packetId)}')" style="min-height: 32px; padding: 4px 14px; font-size: 0.82rem; border-radius: 8px;">
                Pair Device
              </button>
            ` : `
              <svg class="totp-circle-svg" width="28" height="28" viewBox="0 0 28 28">
                <circle class="totp-circle-bg" cx="14" cy="14" r="12" />
                <circle class="totp-circle-fill" id="totpCircleFill-${idx}" cx="14" cy="14" r="12" stroke-dasharray="75.4" stroke-dashoffset="0" transform="rotate(-90 14 14)" />
              </svg>
              <span class="totp-timer-text" id="totpTimerText-${idx}">30s</span>
            `}
          </div>
        </div>
      </div>
    `;
  }).join('');
}

// --- Customer Sign Up ---
async function onCustomerSignUp(e) {
  e.preventDefault();
  clearTotpStatus();

  const mobileEl = $('signupMobile');
  const passwordEl = $('signupPassword');
  const confirmPasswordEl = $('signupConfirmPassword');
  if (!mobileEl || !passwordEl || !confirmPasswordEl) return;

  const mobile = mobileEl.value.trim();
  const password = passwordEl.value.trim();
  const confirmPassword = confirmPasswordEl.value.trim();

  if (!mobile || !password || !confirmPassword) {
    setTotpStatus('All fields are required', 'error');
    return;
  }

  if (password !== confirmPassword) {
    setTotpStatus('Passwords do not match', 'error');
    return;
  }

  try {
    setTotpStatus('Creating account...', 'info');
    await api.customerSignup(mobile, password);
    setTotpStatus('Account created! You can now sign in.', 'success');
    
    // Switch to Sign In tab
    const tabSignin = $('tab-signin');
    if (tabSignin) tabSignin.click();

    const signinMobile = $('signinMobile');
    const signinPassword = $('signinPassword');
    if (signinMobile) signinMobile.value = mobile;
    if (signinPassword) signinPassword.value = '';

    mobileEl.value = '';
    passwordEl.value = '';
    confirmPasswordEl.value = '';
  } catch (err) {
    setTotpStatus(err.message, 'error');
  }
}

// --- Customer Sign In ---
async function onCustomerSignIn(e) {
  e.preventDefault();
  clearTotpStatus();

  const mobileEl = $('signinMobile');
  const passwordEl = $('signinPassword');
  if (!mobileEl || !passwordEl) return;

  const mobile = mobileEl.value.trim();
  const password = passwordEl.value.trim();

  if (!mobile || !password) {
    setTotpStatus('Please fill in all fields', 'error');
    return;
  }

  try {
    setTotpStatus('Signing in...', 'info');
    const res = await api.customerLogin(mobile, password);
    
    customerMobile = res.mobileNumber;
    customerOrders = res.orders;
    if (!Array.isArray(customerOrders)) {
      customerOrders = [];
    }

    sessionStorage.setItem('customer_mobile', customerMobile);
    sessionStorage.setItem('customer_orders', JSON.stringify(customerOrders));

    const portalTitle = $('portal-title');
    const portalDesc = $('portal-desc');
    const authView = $('customer-auth-view');
    const portalView = $('customer-portal-view');

    if (portalTitle) portalTitle.innerText = 'Your Active Orders';
    if (portalDesc) portalDesc.innerText = 'Generate security tokens and unlock your high-value packets.';

    if (authView) authView.classList.add('hidden');
    if (portalView) portalView.classList.remove('hidden');

    mobileEl.value = '';
    passwordEl.value = '';

    renderCarousel();
    startPortalTimer();
    setTotpStatus('Welcome back!', 'success');
  } catch (err) {
    setTotpStatus(err.message, 'error');
  }
}

// --- Carousel TOTP Unlock ---
async function onCarouselUnlock(packetId) {
  clearTotpStatus();
  const order = customerOrders.find(o => o.packetId === packetId);
  if (!order || !order.otp) return;

  try {
    setTotpStatus(`Verifying TOTP token for ${packetId}...`, 'info');
    const res = await api.unlock(packetId, order.otp);

    if (res.success) {
      setTotpStatus(`Lockit ${packetId} successfully unlocked!`, 'success');
      
      // Update status locally
      order.status = 'UNLOCKED';
      sessionStorage.setItem('customer_orders', JSON.stringify(customerOrders));
      renderCarousel();
    } else {
      setTotpStatus(res.message || 'Invalid or expired OTP', 'error');
    }
  } catch (err) {
    if (/tamper/i.test(err.message || '')) {
      enterTamperedState(err.message);
      onCustomerSignOut();
      setTotpStatus('Tamper alert: too many failed attempts', 'error');
      return;
    }
    setTotpStatus(err.message, 'error');
  }
}

// --- Customer Sign Out ---
function onCustomerSignOut() {
  if (portalTimerInterval) {
    clearInterval(portalTimerInterval);
    portalTimerInterval = null;
  }

  customerMobile = null;
  customerOrders = [];

  sessionStorage.removeItem('customer_mobile');
  sessionStorage.removeItem('customer_orders');
  sessionStorage.removeItem('lockit_auth_token');

  const portalTitle = $('portal-title');
  const portalDesc = $('portal-desc');
  const authView = $('customer-auth-view');
  const portalView = $('customer-portal-view');

  if (portalTitle) portalTitle.innerText = 'Customer Login';
  if (portalDesc) portalDesc.innerText = 'Access your active orders and generate security tokens to unlock your Lockit packets.';

  if (authView) authView.classList.remove('hidden');
  if (portalView) portalView.classList.add('hidden');
  clearTotpStatus();
}

// --- Load Session ---
function loadCustomerSession() {
  const savedMobile = sessionStorage.getItem('customer_mobile');
  const savedOrders = sessionStorage.getItem('customer_orders');

  const portalTitle = $('portal-title');
  const portalDesc = $('portal-desc');
  const authView = $('customer-auth-view');
  const portalView = $('customer-portal-view');

  if (savedMobile && savedOrders) {
    customerMobile = savedMobile;
    try {
      customerOrders = JSON.parse(savedOrders);
      if (!Array.isArray(customerOrders)) {
        customerOrders = [];
      }
    } catch {
      customerOrders = [];
    }

    if (portalTitle) portalTitle.innerText = 'Your Active Orders';
    if (portalDesc) portalDesc.innerText = 'Generate security tokens and unlock your high-value packets.';

    if (authView) authView.classList.add('hidden');
    if (portalView) portalView.classList.remove('hidden');

    renderCarousel();
    startPortalTimer();
  } else {
    if (portalTitle) portalTitle.innerText = 'Customer Login';
    if (portalDesc) portalDesc.innerText = 'Access your active orders and generate security tokens to unlock your Lockit packets.';

    if (authView) authView.classList.remove('hidden');
    if (portalView) portalView.classList.add('hidden');
  }
}

// --- Classic Verification Code Flow ---
function getPacketId() {
  const input = $('packetId');
  return input ? input.value.trim() : '';
}

function getCode() {
  const input = $('verificationCode');
  return input ? input.value.trim().replace(/\s+/g, '') : '';
}

function isAlphanumeric(value) {
  return /^[a-z0-9]+$/i.test(value);
}

function setPacketIdDisabled(disabled) {
  const input = $('packetId');
  if (input) input.disabled = disabled;
}

function enterTamperedState(message) {
  clearStatus();
  setStatus(message || 'Tamper alert: too many invalid attempts', 'warning');
  setPacketIdDisabled(true);

  const inputCode = $('verificationCode');
  if (inputCode) inputCode.disabled = true;

  renderTamperedView();
  wireDynamicButtons();
}

async function onCheckPacketId() {
  clearStatus();
  const packetId = getPacketId();

  if (!packetId) {
    setStatus('Enter Packet ID', 'error');
    return;
  }

  try {
    setStatus('Checking Packet ID…', 'info');
    const packet = await api.checkPacket(packetId);

    if (packet && packet.data && packet.data.status === 'TAMPERED') {
      enterTamperedState('Invalid Packet');
      return;
    }

    if (packet && packet.data && packet.data.status === 'UNLOCKED') {
      setStatus('Packet is already unlocked.', 'success');
      setPacketIdDisabled(true);
      renderUnlockedView(packetId);
      wireDynamicButtons();
      return;
    }

    setStatus('Packet ID verified. Enter your Verification ID.', 'success');
    setPacketIdDisabled(true);
    renderVerificationView();
    wireDynamicButtons();
  } catch (e) {
    setStatus(e.message, 'error');
  }
}

async function onVerifyAndUnlock() {
  clearStatus();
  const packetId = getPacketId();
  const code = getCode();

  if (!packetId) {
    setStatus('Enter Packet ID', 'error');
    return;
  }

  if (!code) {
    setStatus('Enter Verification ID', 'error');
    return;
  }

  if (!isAlphanumeric(code)) {
    setStatus('Verification ID must be alphanumeric', 'error');
    return;
  }

  try {
    setStatus('Verifying OTP and Unlocking…', 'info');
    const res = await api.unlock(packetId, code);

    if (res && res.success) {
      setStatus('Package is now Unlocked ', 'success');

      setPacketIdDisabled(true);
      const inputCode = $('verificationCode');
      if (inputCode) inputCode.disabled = true;

      renderUnlockedView(packetId);
      wireDynamicButtons();
    } else {
      setStatus(res.message || 'Invalid or expired OTP', 'error');
    }
  } catch (e) {
    if (/tamper/i.test(e.message || '')) {
      enterTamperedState(e.message);
      return;
    }
    setStatus(e.message, 'error');
  }
}

function onRestart() {
  clearStatus();

  const inputId = $('packetId');
  if (inputId) {
    inputId.disabled = false;
    inputId.value = '';
  }

  const inputCode = $('verificationCode');
  if (inputCode) {
    inputCode.disabled = false;
    inputCode.value = '';
  }

  renderDefaultView();
  wireDynamicButtons();
}

function wireDynamicButtons() {
  const checkBtn = $('checkPacketBtn');
  if (checkBtn) checkBtn.onclick = onCheckPacketId;

  const verifyBtn = $('verifyBtn');
  if (verifyBtn) verifyBtn.onclick = onVerifyAndUnlock;

  const restartBtn = $('restart');
  if (restartBtn) restartBtn.onclick = onRestart;
}

document.addEventListener('DOMContentLoaded', () => {
  renderDefaultView();
  wireDynamicButtons();
  loadCustomerSession();

  // Customer Portal Tab selector
  const tabSignin = $('tab-signin');
  const tabSignup = $('tab-signup');
  if (tabSignin && tabSignup) {
    tabSignin.onclick = () => {
      tabSignin.classList.add('active');
      tabSignup.classList.remove('active');
      $('signinForm').classList.remove('hidden');
      $('signupForm').classList.add('hidden');
      clearTotpStatus();
    };
    tabSignup.onclick = () => {
      tabSignup.classList.add('active');
      tabSignin.classList.remove('active');
      $('signupForm').classList.remove('hidden');
      $('signinForm').classList.add('hidden');
      clearTotpStatus();
    };
  }

  // Customer Forms Submit
  const signinForm = $('signinForm');
  if (signinForm) signinForm.onsubmit = onCustomerSignIn;

  const signupForm = $('signupForm');
  if (signupForm) signupForm.onsubmit = onCustomerSignUp;

  const signOutBtn = $('portalSignOutBtn');
  if (signOutBtn) signOutBtn.onclick = onCustomerSignOut;

  // Keypress support for main packet page
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const el = document.activeElement;
      if (el && el.tagName === 'BUTTON') return;

      if (el && (el.id === 'packetId' || el.id === 'verificationCode')) {
        const checkBtn = $('checkPacketBtn');
        const verifyBtn = $('verifyBtn');
        const restartBtn = $('restart');

        if (checkBtn) {
          e.preventDefault();
          checkBtn.click();
        } else if (verifyBtn) {
          e.preventDefault();
          verifyBtn.click();
        } else if (restartBtn) {
          e.preventDefault();
          restartBtn.click();
        }
      }
    }
  });

  // Close Setup Modal
  const closeSetupBtn = $('closeTotpSetup');
  if (closeSetupBtn) {
    closeSetupBtn.onclick = () => {
      const modal = $('totpSetupModal');
      if (modal) modal.style.display = 'none';
      currentPairingPacketId = null;
    };
  }

  // Verify and Pair button event inside modal
  const verifyPairBtn = $('totpVerifyPairBtn');
  if (verifyPairBtn) {
    verifyPairBtn.onclick = async () => {
      const codeInput = $('totpVerifyCodeInput');
      const statusEl = $('totpSetupModalStatus');
      if (!codeInput || !statusEl || !currentPairingPacketId) return;

      const code = codeInput.value.trim();
      if (!code || code.length !== 6) {
        statusEl.innerText = 'Please enter a 6-digit code';
        statusEl.style.color = '#ef4444'; // Red
        return;
      }

      try {
        statusEl.innerText = 'Verifying...';
        statusEl.style.color = '#38bdf8'; // Sky blue
        
        await api.pairTotp(currentPairingPacketId, code);

        statusEl.innerText = 'Pairing successful!';
        statusEl.style.color = '#10b981'; // Green

        // Update active order paired status
        const order = customerOrders.find(o => o.packetId === currentPairingPacketId);
        if (order) {
          order.paired = true;
          // Save updated orders to local storage
          localStorage.setItem('customer_orders', JSON.stringify(customerOrders));
        }

        setTimeout(async () => {
          const modal = $('totpSetupModal');
          if (modal) modal.style.display = 'none';
          
          // Re-render and sync immediately
          renderCarousel();
          await syncTotpFromServer();
        }, 1500);
      } catch (err) {
        statusEl.innerText = err.message || 'Verification failed';
        statusEl.style.color = '#ef4444'; // Red
      }
    };
  }
});

window.showTotpSetup = async (packetId) => {
  clearTotpStatus();
  currentPairingPacketId = packetId;
  const statusEl = $('totpSetupModalStatus');
  if (statusEl) {
    statusEl.innerText = '';
    delete statusEl.style.color;
  }
  const codeInput = $('totpVerifyCodeInput');
  if (codeInput) {
    codeInput.value = '';
  }
  try {
    setTotpStatus(`Requesting setup for ${packetId}...`, 'info');
    const data = await api.getTotpSetup(packetId);

    // Set QR Code source using the free qrserver API
    const qrImg = $('totpQrCodeImg');
    if (qrImg) {
      qrImg.src = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(data.otpauthUrl)}`;
    }

    // Set secret key
    const secretCode = $('totpSecretKey');
    if (secretCode) {
      secretCode.innerText = data.secret;
    }

    // Show modal
    const modal = $('totpSetupModal');
    if (modal) {
      modal.style.display = 'flex';
    }
    clearTotpStatus();
  } catch (err) {
    setTotpStatus(`Setup failed: ${err.message}`, 'error');
  }
};
