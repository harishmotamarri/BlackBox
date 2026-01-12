# BlackBox OTP Demo (Packet Unlock)

A small demo app showing OTP-based verification for unlocking a packet.

## Stack
- **Backend:** Node.js + Express + SQLite
- **Frontend:** HTML + CSS + Vanilla JS (ES Modules)

## Features
- Generate OTP for a Packet ID (`/api/packet/request-otp`)
- Verify OTP with expiry + attempt counter (`/api/packet/verify-otp`)
- Unlock only after verification (`/api/packet/unlock`)
- Query packet status (`/api/packet/status/:packetId`)

> **Demo note:** OTP is logged to server console. In real systems you would send OTP via SMS/Email and never log it.

## Run locally

### 1) Prerequisites
- Node.js 18+ (recommended)

### 2) Install & start backend
```bash
cd backend
npm install
npm run dev
```

### 3) Open the app
- Go to `http://localhost:5000`

The backend serves the frontend (same-origin) so you avoid CORS issues.

## Environment variables (optional)
- `PORT` (default `5000`)
- `HOST` (default `0.0.0.0`)
- `SQLITE_PATH` (default `backend/blackbox.db`)
- `OTP_TTL_MS` (default 5 minutes)
- `MAX_ATTEMPTS` (default 3)

## Debugging
### Backend
- Quick logs: add `console.log()` around route handlers.
- Node inspect:
  ```bash
  node --inspect src/server.js
  ```
  Then open Chrome -> `chrome://inspect`.
- VS Code: use a Node debug configuration targeting `backend/src/server.js`.

### Frontend
- Use Browser DevTools (Console + Network tabs).
- Check `Network` for failing API calls / wrong paths.

### Database
- Use **DB Browser for SQLite** to inspect `blackbox.db`.

## Typical issues (and fixes)
- **JSON parsing crash (`Unexpected token '<'`)**: the client now reads text first and only parses JSON if valid.
- **API route mismatch / 404s**: frontend uses relative `/api/packet` paths, matching backend.
- **Opening `index.html` via `file://`**: use `http://localhost:5000` instead.

