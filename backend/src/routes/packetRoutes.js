const express = require('express');
const { supabase } = require('../db/database');
const { generateOtp, hashOtp, safeEqualHex } = require('../utils/otp');

const router = express.Router();

const OTP_TTL_MS = Number(process.env.OTP_TTL_MS || 5 * 60 * 1000);
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
  if (packet.status === 'TAMPERED') httpError(403, 'Packet tampered');
}

function blockIfUnlocked(packet) {
  if (packet.status === 'UNLOCKED') httpError(409, 'Packet is already unlocked');
}

// POST /api/packet/request-otp
router.post(
  '/request-otp',
  asyncHandler(async (req, res) => {
    const { packetId } = req.body;
    requireField(packetId, 'Packet ID');

    const packet = await fetchPacketOr404(packetId);
    blockIfTampered(packet);
    blockIfUnlocked(packet);

    const otp = generateOtp();
    const otpHash = hashOtp(otp);

    // DEMO LOGGING: Send to client instead of server console
    // console.error(...) removed

    const expiresAt = Date.now() + OTP_TTL_MS;

    const { error } = await supabase
      .from('packets')
      .update({
        otphash: otpHash,
        current_otp: otp,
        otpexpiresat: expiresAt,
        attempts: 0
      })
      .eq('packetid', packetId);

    if (error) {
      console.error('Supabase update error:', error);
      httpError(500, 'Failed to update packet');
    }

    // Send OTP to client for demo purposes
    res.json({ success: true, message: 'OTP generated', otp });
  })
);

// POST /api/packet/verify-otp
router.post(
  '/verify-otp',
  asyncHandler(async (req, res) => {
    const { packetId, otp } = req.body;
    requireField(packetId, 'Packet ID');
    requireField(otp, 'OTP');

    const packet = await fetchPacketOr404(packetId);
    blockIfTampered(packet);

    if (!packet.otpexpiresat || Date.now() > Number(packet.otpexpiresat)) {
      httpError(410, 'OTP expired');
    }

    const enteredHash = hashOtp(otp);

    if (!safeEqualHex(packet.otphash || '', enteredHash)) {
      const attempts = (packet.attempts || 0) + 1;
      const tamperedNow = attempts >= MAX_ATTEMPTS;

      await supabase
        .from('packets')
        .update({
          attempts: attempts,
          status: tamperedNow ? 'TAMPERED' : packet.status
        })
        .eq('packetid', packetId);

      if (tamperedNow) httpError(403, 'Tamper detected');
      httpError(401, 'Invalid OTP');
    }

    // Success
    await supabase
      .from('packets')
      .update({ status: 'VERIFIED', attempts: 0 })
      .eq('packetid', packetId);

    res.json({ success: true, message: 'OTP verified' });
  })
);

const ADDED_AUTO_LOCK_DELAY_MS = 5 * 60 * 1000; // 5 minutes

// POST /api/packet/unlock
router.post(
  '/unlock',
  asyncHandler(async (req, res) => {
    const { packetId } = req.body;
    requireField(packetId, 'Packet ID');

    const packet = await fetchPacketOr404(packetId);

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

    const packet = await fetchPacketOr404(packetId);

    res.json({
      success: true,
      data: { packetId: packet.packetid, status: packet.status, attempts: packet.attempts || 0 },
    });
  })
);

module.exports = router;
