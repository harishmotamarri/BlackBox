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
    await api.requestOtp(packetId);
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
});
