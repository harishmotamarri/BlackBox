const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// Decode a Base32 string to a Buffer
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
  return Buffer.from(bytes);
}

// Encode a Buffer to a Base32 string
function base32Encode(buffer) {
  let bits = '';
  for (let i = 0; i < buffer.length; i++) {
    bits += buffer[i].toString(2).padStart(8, '0');
  }
  let encoded = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    encoded += BASE32_ALPHABET[parseInt(chunk, 2)];
  }
  return encoded;
}

/**
 * Generate a cryptographically secure random TOTP secret (base32 format, 20 bytes key)
 */
function generateSecret() {
  const bytes = crypto.randomBytes(20);
  return base32Encode(bytes);
}

/**
 * Calculate TOTP code for a given secret and options
 */
function generateTOTP(secret, options = {}) {
  const windowSeconds = options.windowSeconds || 60;
  const algorithm = options.algorithm || 'sha256'; // sha1 or sha256
  const digits = options.digits || 6;
  const time = options.time || Date.now();

  const timeStep = Math.floor(time / (windowSeconds * 1000));
  
  const buffer = Buffer.alloc(8);
  buffer.writeBigInt64BE(BigInt(timeStep), 0);

  const key = base32Decode(secret);
  const hmac = crypto.createHmac(algorithm, key);
  hmac.update(buffer);
  const hmacResult = hmac.digest();

  const offset = hmacResult[hmacResult.length - 1] & 0x0f;
  const code = (
    ((hmacResult[offset] & 0x7f) << 24) |
    ((hmacResult[offset + 1] & 0xff) << 16) |
    ((hmacResult[offset + 2] & 0xff) << 8) |
    (hmacResult[offset + 3] & 0xff)
  ) % Math.pow(10, digits);

  return {
    code: String(code).padStart(digits, '0'),
    timeStep
  };
}

/**
 * Verify TOTP code with previous/next window tolerance
 */
function verifyTOTP(secret, code, options = {}) {
  const windowSeconds = options.windowSeconds || 60;
  const algorithm = options.algorithm || 'sha256';
  const digits = options.digits || 6;
  const time = options.time || Date.now();
  const tolerance = options.tolerance || 1; // +/- 1 window tolerance

  const timeStep = Math.floor(time / (windowSeconds * 1000));

  for (let i = -tolerance; i <= tolerance; i++) {
    const checkStep = timeStep + i;
    const buffer = Buffer.alloc(8);
    buffer.writeBigInt64BE(BigInt(checkStep), 0);

    const key = base32Decode(secret);
    const hmac = crypto.createHmac(algorithm, key);
    hmac.update(buffer);
    const hmacResult = hmac.digest();

    const offset = hmacResult[hmacResult.length - 1] & 0x0f;
    const computedCode = (
      ((hmacResult[offset] & 0x7f) << 24) |
      ((hmacResult[offset + 1] & 0xff) << 16) |
      ((hmacResult[offset + 2] & 0xff) << 8) |
      (hmacResult[offset + 3] & 0xff)
    ) % Math.pow(10, digits);

    const codeStr = String(computedCode).padStart(digits, '0');
    if (codeStr === code) {
      return { valid: true, timeStep: checkStep };
    }
  }

  return { valid: false };
}

// Symmetric encryption/decryption for storing TOTP secret securely in the database
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const DEFAULT_KEY = 'super_secret_fallback_key_for_lockit_totp_auth';

function getEncryptionKey() {
  const envKey = process.env.TOTP_ENCRYPTION_KEY || DEFAULT_KEY;
  return crypto.createHash('sha256').update(envKey).digest();
}

function encryptSecret(secret) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
  
  let encrypted = cipher.update(secret, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag().toString('hex');
  
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decryptSecret(encryptedData) {
  if (!encryptedData || !encryptedData.includes(':')) {
    throw new Error('Invalid encrypted data format');
  }
  const [ivHex, authTagHex, encryptedHex] = encryptedData.split(':');
  const key = getEncryptionKey();
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Derive a deterministic Base32 secret from a mobile number
 */
function deriveSecretFromMobile(mobileNumber) {
  const clean = String(mobileNumber).trim();
  const hash = crypto.createHash('sha256').update(clean).digest();
  return base32Encode(hash.slice(0, 20));
}

module.exports = {
  generateSecret,
  generateTOTP,
  verifyTOTP,
  encryptSecret,
  decryptSecret,
  getEncryptionKey,
  deriveSecretFromMobile
};

