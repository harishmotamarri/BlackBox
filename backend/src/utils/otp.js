const crypto = require('crypto');

function generateOtp() {
  // 6-digit numeric OTP
  return crypto.randomInt(100000, 1000000);
}

function hashOtp(otp) {
  return crypto
    .createHash('sha256')
    .update(String(otp))
    .digest('hex');
}

function safeEqualHex(aHex, bHex) {
  // Prevent timing leaks when comparing hashes
  const a = Buffer.from(String(aHex), 'hex');
  const b = Buffer.from(String(bHex), 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = { generateOtp, hashOtp, safeEqualHex };
