import { api } from './api.js';
import { $, setStatus, clearStatus, renderDefaultView, renderUnlockedView, renderVerificationView, renderTamperedView } from './ui.js';

function getPacketId() {
  const input = $('packetId');
  return input ? input.value.trim() : '';
}

function getCode() {
  const input = $('verificationCode');
  return input ? input.value.trim() : '';
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
      enterTamperedState('Tamper alert: packet already tampered');
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

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const el = document.activeElement;
      if (el && el.tagName === 'BUTTON') return;

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
  });
});
