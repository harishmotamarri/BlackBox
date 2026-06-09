const express = require('express');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const { supabase } = require('../db/database');
const { ensureLockTimeout, ADDED_AUTO_LOCK_DELAY_MS } = require('../utils/packetUtils');
const { generateSecret, verifyTOTP, encryptSecret, decryptSecret, getEncryptionKey } = require('../utils/totp');
const { logEvent } = require('../utils/auditLogger');

const rateLimits = {};
function rateLimit(limit, windowMs) {
  return (req, res, next) => {
    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const now = Date.now();
    if (!rateLimits[ip]) {
      rateLimits[ip] = [];
    }
    rateLimits[ip] = rateLimits[ip].filter(timestamp => now - timestamp < windowMs);
    if (rateLimits[ip].length >= limit) {
      logEvent(ip, req.body.packetId, req.body.userId || 'N/A', 'RATE_LIMIT_EXCEEDED', `IP ${ip} exceeded rate limit on ${req.originalUrl}`);
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }
    rateLimits[ip].push(now);
    next();
  };
}

const router = express.Router();

const MAX_ATTEMPTS = Number(process.env.MAX_ATTEMPTS || 3);

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

function httpError(statusCode, message) {
  const err = new Error(message);
  err.statusCode = statusCode;
  throw err;
}

function requireField(val, name) {
  if (val === undefined || val === null || String(val).trim() === '') {
    httpError(400, `${name} required`);
  }
}

function requireAlphanumeric(val, name) {
  if (!/^[a-z0-9]+$/i.test(String(val).trim())) {
    httpError(400, `${name} must be alphanumeric`);
  }
}

async function fetchPacketOr404(packetId) {
  const { data, error } = await supabase
    .from('packets')
    .select('*')
    .eq('packetid', packetId)
    .single();

  if (error || !data) {
    // If error code is 'PGRST116' it means 0 rows returns from single()
    if (error && error.code !== 'PGRST116') {
      console.error('Supabase error fetchPacket:', error);
      httpError(500, 'Database error');
    }
    httpError(404, 'Packet not found');
  }
  return data;
}

function blockIfTampered(packet) {
  if (packet.status === 'TAMPERED') httpError(403, 'Tamper alert: packet already tampered');
}

function blockIfUnlocked(packet) {
  if (packet.status === 'UNLOCKED') httpError(409, 'Packet is already unlocked');
}

// GET /api/packet/:packetId/totp/setup
router.get(
  '/:packetId/totp/setup',
  asyncHandler(async (req, res) => {
    const { packetId } = req.params;
    requireField(packetId, 'Packet ID');

    const packet = await fetchPacketOr404(packetId);

    let secretKey;
    if (!packet.otphash) {
      secretKey = generateSecret();
      const encryptedSecret = encryptSecret(secretKey);
      await supabase
        .from('packets')
        .update({ otphash: encryptedSecret })
        .eq('packetid', packetId);
    } else {
      secretKey = decryptSecret(packet.otphash);
    }

    const otpauthUrl = `otpauth://totp/BlackBox:${packetId}?secret=${secretKey}&issuer=BlackBox`;

    res.json({
      secret: secretKey,
      otpauthUrl: otpauthUrl
    });
  })
);

// POST /api/packet/:packetId/totp/pair
router.post(
  '/:packetId/totp/pair',
  asyncHandler(async (req, res) => {
    const { packetId } = req.params;
    const { code } = req.body;
    requireField(packetId, 'Packet ID');
    requireField(code, 'Code');

    const packet = await fetchPacketOr404(packetId);

    if (!packet.otphash) {
      httpError(400, 'TOTP is not configured for this packet');
    }

    let secretKey;
    try {
      secretKey = decryptSecret(packet.otphash);
    } catch (e) {
      httpError(500, 'Security decryption error');
    }

    const valid = speakeasy.totp.verify({
      secret: secretKey,
      encoding: 'base32',
      token: code,
      window: 1
    });
    if (!valid) {
      httpError(400, 'Invalid verification code. Pairing failed.');
    }

    // Update pairing status to 'true' in database
    const { error } = await supabase
      .from('packets')
      .update({ totpSecret: 'true' })
      .eq('packetid', packetId);

    if (error) {
      console.error('Supabase error during pairing update:', error);
      httpError(500, 'Failed to save pairing confirmation');
    }

    res.json({ success: true, message: 'Pairing successful' });
  })
);

// POST /api/packet/verify-code
router.post(
  '/verify-code',
  asyncHandler(async (req, res) => {
    const { packetId, verificationCode } = req.body;
    requireField(packetId, 'Packet ID');
    requireField(verificationCode, 'Verification Code');

    const cleanCode = String(verificationCode).trim().replace(/\s+/g, '');
    requireAlphanumeric(cleanCode, 'Verification Code');

    const packet = await fetchPacketOr404(packetId);
    blockIfUnlocked(packet);

    let isValid = false;
    let isTotpValid = false;
    let newCurrentOtp = packet.current_otp;

    if (packet.otphash) {
      try {
        const secret = decryptSecret(packet.otphash);
        const { valid, timeStep } = verifyTOTP(secret, cleanCode);
        isTotpValid = valid;
        
        // Replay attack prevention
        if (isTotpValid && packet.current_otp) {
          if (/^\d+$/.test(packet.current_otp) && timeStep <= Number(packet.current_otp)) {
            isTotpValid = false;
          }
        }
        if (isTotpValid) {
          newCurrentOtp = String(timeStep);
          isValid = true;
        }
      } catch (e) {
        console.error('Decryption or TOTP verification failed:', e);
      }
    }

    // If TOTP was not verified, check tamper state and fall back to classic verification code
    if (!isTotpValid) {
      blockIfTampered(packet);
      if (!packet.otphash) {
        isValid = (packet.current_otp === cleanCode);
      }
    }

    if (!isValid) {
      const attempts = (packet.attempts || 0) + 1;
      const tamperedNow = attempts >= MAX_ATTEMPTS;

      await supabase
        .from('packets')
        .update({
          attempts: attempts,
          status: tamperedNow ? 'TAMPERED' : packet.status
        })
        .eq('packetid', packetId);

      if (tamperedNow) httpError(403, 'Tamper alert: too many invalid attempts');
      httpError(401, 'Invalid Verification Code');
    }

    // Success
    await supabase
      .from('packets')
      .update({ 
        status: 'VERIFIED', 
        attempts: 0,
        current_otp: newCurrentOtp
      })
      .eq('packetid', packetId);

    res.json({ success: true, message: 'Verification Code valid' });
  })
);

// POST /api/packet/unlock
router.post(
  '/unlock',
  asyncHandler(async (req, res) => {
    const { packetId, otp } = req.body;
    requireField(packetId, 'Packet ID');

    const packet = await fetchPacketOr404(packetId);

    if (packet.status === 'UNLOCKED') {
      return res.json({
        success: true,
        alreadyUnlocked: true,
        message: 'Packet is already unlocked'
      });
    }

    if (otp !== undefined) {
      if (!packet.totpSecret || packet.totpSecret !== 'true') {
        return res.status(400).json({
          success: false,
          message: 'Authenticator not paired yet'
        });
      }
      // Validate OTP using speakeasy and packet-specific secret
      let secretKey;
      if (!packet.otphash) {
        secretKey = generateSecret();
        const encryptedSecret = encryptSecret(secretKey);
        await supabase
          .from('packets')
          .update({ otphash: encryptedSecret })
          .eq('packetid', packetId);
      } else {
        secretKey = decryptSecret(packet.otphash);
      }

      const verified = speakeasy.totp.verify({
        secret: secretKey,
        encoding: 'base32',
        token: otp,
        window: 1
      });

      if (!verified) {
        // Increment attempts, check if tampered
        const attempts = (packet.attempts || 0) + 1;
        const tamperedNow = attempts >= MAX_ATTEMPTS;

        await supabase
          .from('packets')
          .update({
            attempts: attempts,
            status: tamperedNow ? 'TAMPERED' : packet.status
          })
          .eq('packetid', packetId);

        const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
        logEvent(ip, packetId, 'CUSTOMER', tamperedNow ? 'TAMPER_ALERT' : 'UNLOCK_FAILED', `Invalid TOTP code. New attempts: ${attempts}`);

        if (tamperedNow) {
          httpError(403, 'Tamper alert: too many invalid attempts');
        }
        return res.json({
          success: false,
          message: 'Invalid or expired OTP'
        });
      }
    } else {
      // Legacy behavior fallback
      if (packet.status !== 'VERIFIED') {
        httpError(403, 'Unauthorized');
      }
    }

    // Success unlock logic
    await supabase
      .from('packets')
      .update({ status: 'UNLOCKED', attempts: 0 })
      .eq('packetid', packetId);

    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    logEvent(ip, packetId, 'CUSTOMER', 'UNLOCK_SUCCESS', `Packet unlocked successfully.`);

    // Auto-lock after 5 minutes
    setTimeout(async () => {
      console.log(`Auto-locking packet: ${packetId}`);
      const { error } = await supabase
        .from('packets')
        .update({ status: 'LOCKED', attempts: 0 })
        .eq('packetid', packetId)
        .eq('status', 'UNLOCKED'); // Only lock if still unlocked

      if (error) {
        console.error(`Failed to auto-lock packet ${packetId}:`, error);
      } else {
        logEvent('SYSTEM', packetId, 'SYSTEM', 'AUTO_LOCK', 'Packet automatically locked after 5 minutes');
      }
    }, ADDED_AUTO_LOCK_DELAY_MS);

    res.json({ success: true, message: 'Packet unlocked' });
  })
);

// GET /api/packet/status/:packetId
router.get(
  '/status/:packetId',
  asyncHandler(async (req, res) => {
    const { packetId } = req.params;
    requireField(packetId, 'Packet ID');

    let packet = await fetchPacketOr404(packetId);
    packet = await ensureLockTimeout(packet);

    res.json({
      success: true,
      data: { packetId: packet.packetid, status: packet.status, attempts: packet.attempts || 0 },
    });
  })
);

// POST /api/packet/register-totp
router.post(
  '/register-totp',
  rateLimit(10, 60 * 1000), // 10 per min
  asyncHandler(async (req, res) => {
    const { packetId, mobileNumber, userId } = req.body;
    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

    requireField(packetId, 'Packet ID');
    requireField(mobileNumber, 'Mobile Number');
    requireField(userId, 'User ID');

    const packet = await fetchPacketOr404(packetId);
    blockIfTampered(packet);

    if (packet.registered_number.trim() !== mobileNumber.trim()) {
      logEvent(ip, packetId, userId, 'REGISTRATION_FAILED', `Mobile number mismatch: provided '${mobileNumber}', expected '${packet.registered_number}'`);
      httpError(401, 'Invalid mobile number for this packet');
    }

    const secret = generateSecret();
    const encryptedSecret = encryptSecret(secret);

    const { error } = await supabase
      .from('packets')
      .update({
        otphash: encryptedSecret,
        attempts: 0,
        user_details: userId.trim(),
        status: 'LOCKED',
        current_otp: null
      })
      .eq('packetid', packetId);

    if (error) {
      console.error('Supabase registration error:', error);
      logEvent(ip, packetId, userId, 'REGISTRATION_DB_ERROR', `Failed to update packet in DB: ${error.message}`);
      httpError(500, 'Database registration failed');
    }

    logEvent(ip, packetId, userId, 'REGISTRATION_SUCCESS', 'Successfully registered TOTP secret');

    res.json({
      success: true,
      secret: secret,
      message: 'TOTP registration successful'
    });
  })
);

// POST /api/packet/unlock-totp
router.post(
  '/unlock-totp',
  rateLimit(5, 60 * 1000), // 5 per min
  asyncHandler(async (req, res) => {
    const { packetId, userId, totp } = req.body;
    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

    requireField(packetId, 'Packet ID');
    requireField(userId, 'User ID');
    requireField(totp, 'TOTP Code');

    const packet = await fetchPacketOr404(packetId);
    blockIfUnlocked(packet);

    if (!packet.otphash) {
      logEvent(ip, packetId, userId, 'UNLOCK_FAILED', 'Attempted unlock on non-TOTP registered packet');
      httpError(400, 'Packet has not been registered for TOTP authentication');
    }

    if (!packet.totpSecret || packet.totpSecret !== 'true') {
      logEvent(ip, packetId, userId, 'UNLOCK_FAILED', 'Attempted unlock on non-paired packet');
      httpError(400, 'Packet has not been paired with Authenticator');
    }

    let secret;
    try {
      secret = decryptSecret(packet.otphash);
    } catch (e) {
      logEvent(ip, packetId, userId, 'DECRYPTION_ERROR', 'Failed to decrypt TOTP secret from DB');
      httpError(500, 'Internal security decryption error');
    }

    let { valid, timeStep } = verifyTOTP(secret, totp);

    // Replay attack prevention
    if (valid && packet.current_otp) {
      if (timeStep <= Number(packet.current_otp)) {
        logEvent(ip, packetId, userId, 'REPLAY_ATTACK_DETECTED', `Replay attack detected for time-step: ${timeStep} (last verified: ${packet.current_otp})`);
        valid = false;
      }
    }

    if (!valid) {
      // If the TOTP is invalid, check tamper state (and block if already tampered)
      blockIfTampered(packet);

      const attempts = (packet.attempts || 0) + 1;
      const tamperedNow = attempts >= MAX_ATTEMPTS;

      await supabase
        .from('packets')
        .update({
          attempts: attempts,
          status: tamperedNow ? 'TAMPERED' : packet.status
        })
        .eq('packetid', packetId);

      logEvent(ip, packetId, userId, tamperedNow ? 'TAMPER_ALERT' : 'UNLOCK_FAILED', `Invalid TOTP code. New attempts: ${attempts}`);

      if (tamperedNow) {
        httpError(403, 'Tamper alert: too many invalid attempts');
      }
      httpError(401, 'Invalid TOTP code');
    }

    // Success - generate signed authorization token (expiring in 5 minutes)
    const expiresAt = Date.now() + 5 * 60 * 1000;
    const payload = JSON.stringify({ packetId, userId, expiresAt });
    const signature = crypto.createHmac('sha256', getEncryptionKey()).update(payload).digest('hex');
    const token = `${Buffer.from(payload).toString('base64')}.${signature}`;

    // Reset attempts, update status to UNLOCKED, store timeStep to prevent replay
    const { error } = await supabase
      .from('packets')
      .update({
        status: 'UNLOCKED',
        attempts: 0,
        current_otp: String(timeStep)
      })
      .eq('packetid', packetId);

    if (error) {
      logEvent(ip, packetId, userId, 'UNLOCK_DB_ERROR', `Failed to set packet status to UNLOCKED: ${error.message}`);
      httpError(500, 'Database unlock status update failed');
    }

    logEvent(ip, packetId, userId, 'UNLOCK_SUCCESS', `Packet unlocked using TOTP. TimeStep: ${timeStep}`);

    // Auto-lock after 5 minutes
    setTimeout(async () => {
      console.log(`Auto-locking packet: ${packetId}`);
      const { error } = await supabase
        .from('packets')
        .update({ status: 'LOCKED', attempts: 0 })
        .eq('packetid', packetId)
        .eq('status', 'UNLOCKED'); // Only lock if still unlocked

      if (error) {
        console.error(`Auto-lock failed for packet ${packetId}:`, error);
      } else {
        logEvent('SYSTEM', packetId, 'SYSTEM', 'AUTO_LOCK', 'Packet automatically locked after 5 minutes');
      }
    }, ADDED_AUTO_LOCK_DELAY_MS);

    res.json({
      success: true,
      message: 'Package unlocked successfully',
      token,
      expiresAt
    });
  })
);

// POST /api/packet/customer-signup
router.post(
  '/customer-signup',
  asyncHandler(async (req, res) => {
    const { mobileNumber, password } = req.body;
    requireField(mobileNumber, 'Mobile Number');
    requireField(password, 'Password');

    // Check if customer already exists in customers table
    const { data: existing, error: fetchErr } = await supabase
      .from('customers')
      .select('*')
      .eq('username', mobileNumber.trim())
      .single();

    if (existing) {
      httpError(400, 'Mobile number already registered');
    }

    if (fetchErr && fetchErr.code !== 'PGRST116') {
      console.error('Signup fetch error:', fetchErr);
      httpError(500, 'Database query failed');
    }

    // Insert new customer
    const { error: insertErr } = await supabase
      .from('customers')
      .insert([{
        username: mobileNumber.trim(),
        password: password.trim()
      }]);

    if (insertErr) {
      console.error('Signup insert error:', insertErr);
      httpError(500, 'Registration failed');
    }

    res.json({ success: true, message: 'Customer registered successfully' });
  })
);

// POST /api/packet/customer-login
router.post(
  '/customer-login',
  asyncHandler(async (req, res) => {
    const { mobileNumber, password } = req.body;
    requireField(mobileNumber, 'Mobile Number');
    requireField(password, 'Password');

    // Retrieve user credentials
    const { data: user, error: userErr } = await supabase
      .from('customers')
      .select('*')
      .eq('username', mobileNumber.trim())
      .single();

    if (userErr || !user || user.password !== password.trim()) {
      httpError(401, 'Invalid mobile number or password');
    }

    // Find all active packets (orders) for this customer (check registered_number or user_details containing the mobile number)
    const { data: packets, error: packetsErr } = await supabase
      .from('packets')
      .select('*')
      .eq('is_active', true)
      .or(`registered_number.eq.${mobileNumber.trim()},user_details.ilike.%${mobileNumber.trim()}%`);

    if (packetsErr) {
      console.error('Login packets fetch error:', packetsErr);
      httpError(500, 'Failed to fetch customer orders');
    }

    const activeOrders = [];

    // For each active packet, make sure it has a TOTP secret
    for (const packet of packets) {
      let secret = null;
      if (!packet.otphash) {
        secret = generateSecret();
        const encryptedSecret = encryptSecret(secret);

        const { error: updateErr } = await supabase
          .from('packets')
          .update({
            otphash: encryptedSecret,
            attempts: 0,
            status: 'LOCKED',
            current_otp: null
          })
          .eq('packetid', packet.packetid);

        if (updateErr) {
          console.error(`Failed to auto-generate TOTP for packet ${packet.packetid}:`, updateErr);
          secret = null;
        }
      } else {
        try {
          secret = decryptSecret(packet.otphash);
        } catch (e) {
          console.error(`Failed to decrypt secret for packet ${packet.packetid}. Regenerating new secret. Error:`, e.message);
          secret = generateSecret();
          const encryptedSecret = encryptSecret(secret);
          const { error: updateErr } = await supabase
            .from('packets')
            .update({
              otphash: encryptedSecret,
              attempts: 0,
              status: 'LOCKED',
              current_otp: null
            })
            .eq('packetid', packet.packetid);
          if (updateErr) {
            console.error(`Failed to update regenerated TOTP secret for packet ${packet.packetid}:`, updateErr);
          }
        }
      }

      activeOrders.push({
        packetId: packet.packetid,
        secret: secret,
        paired: packet.totpSecret === 'true',
        status: packet.status,
        fromLocation: packet.from_location || '-',
        toLocation: packet.to_location || '-',
        packetType: packet.packet_type || 'Standard',
        authType: packet.auth_type || '-',
        userDetails: packet.user_details || '-'
      });
    }

    res.json({
      success: true,
      message: 'Login successful',
      mobileNumber: mobileNumber.trim(),
      orders: activeOrders
    });
  })
);

module.exports = router;
