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
let activeOrderIndex = 0;
let portalTimerInterval = null;

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

// --- Carousel Countdown Loop ---
function startPortalTimer() {
  if (portalTimerInterval) clearInterval(portalTimerInterval);

  async function update() {
    if (customerOrders.length === 0) return;
    const order = customerOrders[activeOrderIndex];
    if (!order || !order.secret) return;

    try {
      const code = await generateBrowserTOTP(order.secret);
      const formattedCode = `${code.slice(0, 3)} ${code.slice(3)}`;
      
      const codeEl = $(`carouselTotpCode-${activeOrderIndex}`);
      if (codeEl) codeEl.innerText = formattedCode;

      const now = Date.now();
      const secondsRemaining = 60 - Math.floor((now / 1000) % 60);

      const timerEl = $(`carouselTimer-${activeOrderIndex}`);
      if (timerEl) timerEl.innerText = `Refresh in ${secondsRemaining}s`;

      const progressFill = $(`carouselProgressFill-${activeOrderIndex}`);
      if (progressFill) {
        const pct = (secondsRemaining / 60) * 100;
        progressFill.style.width = `${pct}%`;

        if (secondsRemaining <= 10) {
          progressFill.classList.add('warning');
        } else {
          progressFill.classList.remove('warning');
        }
      }
    } catch (err) {
      console.error('Failed to generate carousel TOTP code:', err);
    }
  }

  update();
  portalTimerInterval = setInterval(update, 1000);
}

// --- Render Carousel Slides ---
function renderCarousel() {
  const container = $('carousel-slides-container');
  const indicator = $('carouselIndicator');
  const prevBtn = $('carouselPrevBtn');
  const nextBtn = $('carouselNextBtn');
  
  if (!container) return;

  if (customerOrders.length === 0) {
    container.innerHTML = `
      <div class="carousel-slide active">
        <p style="text-align: center; color: var(--muted); margin: 20px 0;">No active orders found.</p>
      </div>
    `;
    if (indicator) indicator.innerText = 'Order 0 of 0';
    if (prevBtn) prevBtn.disabled = true;
    if (nextBtn) nextBtn.disabled = true;
    return;
  }

  // Update navigation buttons & indicators
  if (prevBtn) prevBtn.disabled = activeOrderIndex === 0;
  if (nextBtn) nextBtn.disabled = activeOrderIndex === customerOrders.length - 1;
  if (indicator) indicator.innerText = `Order ${activeOrderIndex + 1} of ${customerOrders.length}`;

  // Render slides
  container.innerHTML = customerOrders.map((order, idx) => {
    const isActiveClass = idx === activeOrderIndex ? 'active' : '';
    return `
      <div class="carousel-slide ${isActiveClass}" data-index="${idx}">
        <div class="totp-display-container">
          <div class="order-metadata-card" style="margin-bottom: 15px; border-color: rgba(56, 189, 248, 0.25); background: rgba(56, 189, 248, 0.03); text-align: left;">
            <div class="order-metadata-row" style="margin-bottom: 0;">
              <span>Packet ID:</span>
              <strong>${escapeHtml(order.packetId)}</strong>
            </div>
          </div>
          <div class="totp-code" id="carouselTotpCode-${idx}">000 000</div>
          <div class="totp-progress-bar">
            <div class="totp-progress-fill" id="carouselProgressFill-${idx}"></div>
          </div>
          <div class="totp-timer" id="carouselTimer-${idx}">Refresh in 60s</div>
        </div>
      </div>
    `;
  }).join('');
}

function showPrevOrder() {
  if (activeOrderIndex > 0) {
    activeOrderIndex--;
    renderCarousel();
    startPortalTimer();
  }
}

function showNextOrder() {
  if (activeOrderIndex < customerOrders.length - 1) {
    activeOrderIndex++;
    renderCarousel();
    startPortalTimer();
  }
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
    activeOrderIndex = 0;

    localStorage.setItem('customer_mobile', customerMobile);
    localStorage.setItem('customer_orders', JSON.stringify(customerOrders));

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
  if (!order || !order.secret) return;

  try {
    setTotpStatus(`Verifying TOTP token for ${packetId}...`, 'info');
    const currentTotp = await generateBrowserTOTP(order.secret);
    const res = await api.unlockTotp(packetId, customerMobile, currentTotp);

    if (res.token) {
      sessionStorage.setItem('lockit_auth_token', res.token);
    }

    setTotpStatus(`Lockit ${packetId} successfully unlocked!`, 'success');
    
    // Update status locally
    order.status = 'UNLOCKED';
    localStorage.setItem('customer_orders', JSON.stringify(customerOrders));
    renderCarousel();
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
  activeOrderIndex = 0;

  localStorage.removeItem('customer_mobile');
  localStorage.removeItem('customer_orders');
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
  const savedMobile = localStorage.getItem('customer_mobile');
  const savedOrders = localStorage.getItem('customer_orders');

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
    activeOrderIndex = 0;

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
    setStatus('Verifying ID…', 'info');
    await api.verifyCode(packetId, code);
    setStatus('Verification ID verified. Unlocking…', 'success');
    await api.unlock(packetId);
    setStatus('Package is now Unlocked ', 'success');

    setPacketIdDisabled(true);
    const inputCode = $('verificationCode');
    if (inputCode) inputCode.disabled = true;

    renderUnlockedView(packetId);
    wireDynamicButtons();
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

  // Carousel controls
  const prevBtn = $('carouselPrevBtn');
  if (prevBtn) prevBtn.onclick = showPrevOrder;

  const nextBtn = $('carouselNextBtn');
  if (nextBtn) nextBtn.onclick = showNextOrder;

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
});
