import { api } from './api.js';
import { $, setStatus, clearStatus, renderRequestOtpView, renderVerifyOtpView, renderUnlockedView } from './ui.js';

function getPacketId() {
  const input = $('packetId');
  return input ? input.value.trim() : '';
}

function getOtp() {
  const input = $('otp');
  return input ? input.value.trim() : '';
}

async function onRequestOtp() {
  clearStatus();

  const packetId = getPacketId();
  if (!packetId) {
    setStatus('Please enter Packet ID', 'error');
    return;
  }

  try {
    setStatus('Generating OTP…', 'info');
    const res = await api.requestOtp(packetId);

    // Log OTP to console for the user
    if (res.otp) {
      console.log(`%c OTP for ${packetId}: ${res.otp} `, 'background: #222; color: #bada55; font-size: 16px; padding: 4px; border-radius: 4px;');
    }

    setStatus('OTP generated.', 'success');

    // Disable Packet ID input
    const input = $('packetId');
    if (input) input.disabled = true;

    renderVerifyOtpView(packetId);
    wireDynamicButtons();
  } catch (e) {
    setStatus(e.message, 'error');
  }
}

async function onVerifyOtp() {
  clearStatus();

  const packetId = getPacketId();
  const otp = getOtp();

  if (!packetId || !otp) {
    setStatus('Enter both Packet ID and OTP', 'error');
    return;
  }

  try {
    setStatus('Verifying OTP…', 'info');
    await api.verifyOtp(packetId, otp);
    setStatus('OTP verified. Unlocking…', 'success');
    await api.unlock(packetId);
    setStatus('Package is now Unlocked ', 'success');
    renderUnlockedView(packetId);
    wireDynamicButtons();
  } catch (e) {
    setStatus(e.message, 'error');
  }
}

function onRestart() {
  clearStatus();

  const input = $('packetId');
  if (input) {
    input.disabled = false;
    input.value = '';
  }

  renderRequestOtpView();
  wireDynamicButtons();
}

function wireDynamicButtons() {
  const requestOtpBtn = $('requestOtp');
  if (requestOtpBtn) requestOtpBtn.onclick = onRequestOtp;

  const verifyOtpBtn = $('verifyOtp');
  if (verifyOtpBtn) verifyOtpBtn.onclick = onVerifyOtp;

  const restartBtn = $('restart');
  if (restartBtn) restartBtn.onclick = onRestart;
}

document.addEventListener('DOMContentLoaded', () => {
  // Ensure initial UI is correct even if HTML changes
  renderRequestOtpView();
  wireDynamicButtons();

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const el = document.activeElement;
      // If the user already focused a button, let the browser handle the click
      if (el && el.tagName === 'BUTTON') return;

      const requestBtn = $('requestOtp');
      const verifyBtn = $('verifyOtp');
      const restartBtn = $('restart');

      if (verifyBtn) {
        // Prevent default form submission if any, and trigger click
        e.preventDefault();
        verifyBtn.click();
      } else if (requestBtn) {
        e.preventDefault();
        requestBtn.click();
      } else if (restartBtn) {
        e.preventDefault();
        restartBtn.click();
      }
    }
  });
});
