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

export function renderDefaultView() {
  const title = $('card-title');
  const action = $('action');
  const note = $('note');

  if (title) title.innerText = 'Enter Packet ID';
  if (note) note.innerText = 'First verify the Packet ID to continue.';

  if (!action) return;
  action.innerHTML = `
    <button class="btn btn-primary btn-full" id="checkPacketBtn" type="button">
      Check Packet ID
    </button>
  `;
}

export function renderVerificationView() {
  const title = $('card-title');
  const action = $('action');
  const note = $('note');

  if (title) title.innerText = 'Verify Packet';
  if (note) note.innerText = 'Enter the alphanumeric Verification ID to unlock the packet.';

  if (!action) return;
  action.innerHTML = `
    <label class="small" for="verificationCode">Verification ID</label>
    <input
      id="verificationCode"
      class="input-field"
      inputmode="text"
      autocomplete="off"
      spellcheck="false"
      placeholder="Enter verification ID"
      pattern="[A-Za-z0-9]+"
    />
    <button class="btn btn-primary btn-full" id="verifyBtn" type="button">
      Verify and Unlock
    </button>
  `;
}

export function renderTamperedView() {
  const title = $('card-title');
  const action = $('action');
  const note = $('note');

  if (title) title.innerText = 'Tamper Alert';
  if (note) note.innerText = 'Too many invalid attempts were detected. The packet is locked for safety.';

  if (!action) return;
  action.innerHTML = `
    <button class="btn btn-primary btn-full" id="restart" type="button">
      Unlock another packet
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
