const express = require('express');
const { supabase } = require('../db/database');

const router = express.Router();

const asyncHandler = (fn) => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

function httpError(statusCode, message) {
    const err = new Error(message);
    err.statusCode = statusCode;
    throw err;
}

async function fetchPacketOr404(packetId) {
    const { data, error } = await supabase
        .from('packets')
        .select('*')
        .eq('packetid', packetId)
        .single();

    if (error || !data) {
        if (error && error.code !== 'PGRST116') {
            console.error('Supabase error fetchPacket:', error);
            httpError(500, 'Database error');
        }
        httpError(404, 'Packet not found');
    }
    return data;
}

// GET /api/hardware/verification-code/:packetId
// Returns the current verification code if it exists and is still valid
router.get(
    '/verification-code/:packetId',
    asyncHandler(async (req, res) => {
        const { packetId } = req.params;

        if (!packetId) httpError(400, 'Packet ID required');

        const packet = await fetchPacketOr404(packetId);

        // Check expiry
        if (!packet.otpexpiresat || Date.now() > Number(packet.otpexpiresat)) {
            // Verification code expired or not set
            httpError(404, 'No valid verification code');
        }

        // Check if verification code exists
        if (!packet.current_otp) {
            httpError(404, 'No verification code generated');
        }

        // Return the plain verification code
        res.json({
            success: true,
            verificationCode: packet.current_otp
        });
    })
);

// GET /api/hardware/command/:packetId
// Returns "OPEN" if status is UNLOCKED
router.get(
    '/command/:packetId',
    asyncHandler(async (req, res) => {
        const { packetId } = req.params;

        if (!packetId) httpError(400, 'Packet ID required');

        const packet = await fetchPacketOr404(packetId);

        if (packet.status === 'UNLOCKED') {
            return res.json({ command: 'OPEN' });
        }

        res.json({ command: 'WAIT' });
    })
);

module.exports = router;
