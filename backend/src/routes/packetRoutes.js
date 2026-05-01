const express = require('express');
const { supabase } = require('../db/database');
const { ensureLockTimeout, ADDED_AUTO_LOCK_DELAY_MS } = require('../utils/packetUtils');

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

// POST /api/packet/verify-code
router.post(
  '/verify-code',
  asyncHandler(async (req, res) => {
    const { packetId, verificationCode } = req.body;
    requireField(packetId, 'Packet ID');
    requireField(verificationCode, 'Verification Code');
    requireAlphanumeric(verificationCode, 'Verification Code');

    const packet = await fetchPacketOr404(packetId);
    blockIfTampered(packet);
    blockIfUnlocked(packet);

    if (packet.current_otp !== verificationCode) {
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
      .update({ status: 'VERIFIED', attempts: 0 })
      .eq('packetid', packetId);

    res.json({ success: true, message: 'Verification Code valid' });
  })
);

// POST /api/packet/unlock
router.post(
  '/unlock',
  asyncHandler(async (req, res) => {
    const { packetId } = req.body;
    requireField(packetId, 'Packet ID');

    const packet = await fetchPacketOr404(packetId);

    if (packet.status === 'UNLOCKED') {
      return res.json({
        success: true,
        alreadyUnlocked: true,
        message: 'Packet is already unlocked'
      });
    }

    if (packet.status !== 'VERIFIED') {
      httpError(403, 'Unauthorized');
    }

    await supabase
      .from('packets')
      .update({ status: 'UNLOCKED' })
      .eq('packetid', packetId);

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
        console.log(`Packet ${packetId} locked successfully.`);
      }
    }, ADDED_AUTO_LOCK_DELAY_MS);

    res.json({ success: true, message: 'Package unlocked' });
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

module.exports = router;
