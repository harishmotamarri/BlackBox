export function $(id) {
  return document.getElementById(id);
}

export function setStatus(message, type = 'info') {
  const el = $('status');
  if (!el) return;
  el.innerHTML = message;
  el.dataset.type = type;
}

export function clearStatus() {
  const el = $('status');
  if (!el) return;
  el.innerHTML = '';
  delete el.dataset.type;
}

export function renderRequestOtpView() {
  const title = $('card-title');
  const action = $('action');
  const note = $('note');

  if (title) title.innerText = 'Enter Packet ID';
  if (note) note.innerText = 'Enter the Packet ID printed on your BlackBox.';

  if (!action) return;
  action.innerHTML = `
    <button class="btn btn-primary btn-full" id="requestOtp" type="button">
      Generate OTP
    </button>
  `;
}

export function renderVerifyOtpView(packetId) {
  const title = $('card-title');
  const action = $('action');
  const note = $('note');

  if (title) title.innerText = 'OTP - Verification';
  if (note) note.innerText = 'OTP has been sent to the registered receiver (demo).';

  if (!action) return;
  action.innerHTML = `
    <p>Please, Enter OTP for Packet ID: <strong>${escapeHtml(packetId)}</strong></p>

    <label class="small">OTP</label>
    <input id="otp" class="input-field" placeholder="Enter 6-digit OTP" inputmode="numeric" autocomplete="one-time-code" />

    <button class="btn btn-primary btn-full" id="verifyOtp" type="button">
      Verify OTP
    </button>
  `;
}

export function renderUnlockedView(packetId) {
  const title = $('card-title');
  const action = $('action');
  const note = $('note');

  if (title) title.innerText = 'Unlocked';
  if (note) note.innerText = 'Packet is unlocked.';

  if (!action) return;
  action.innerHTML = `
    <button class="btn btn-primary btn-full" id="restart" type="button">
      Unlock another packet
    </button>
  `;
}

function escapeHtml(str) {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}
