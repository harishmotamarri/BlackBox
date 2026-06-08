const fs = require('fs');
const path = require('path');

const LOGS_DIR = path.join(__dirname, '..', '..', 'logs');
const LOG_FILE = path.join(LOGS_DIR, 'audit.log');

function ensureLogDirExists() {
  if (!fs.existsSync(LOGS_DIR)) {
    fs.mkdirSync(LOGS_DIR, { recursive: true });
  }
}

/**
 * Log a security-relevant audit event
 * @param {string} ip The source IP address
 * @param {string} packetId The associated packet ID
 * @param {string} userId The associated user ID
 * @param {string} eventType The type of event (e.g. REGISTRATION, UNLOCK_SUCCESS, UNLOCK_FAIL, RATE_LIMIT)
 * @param {string} description Detailed description of the event
 */
function logEvent(ip, packetId, userId, eventType, description) {
  try {
    ensureLogDirExists();
    const timestamp = new Date().toISOString();
    const logLine = `[${timestamp}] [IP: ${ip}] [Packet: ${packetId || 'N/A'}] [User: ${userId || 'N/A'}] [Event: ${eventType}] - ${description}\n`;
    
    fs.appendFileSync(LOG_FILE, logLine, 'utf8');
    console.log(`[AUDIT LOG] ${logLine.trim()}`);
  } catch (err) {
    console.error('Failed to write to audit log:', err);
  }
}

module.exports = {
  logEvent
};
