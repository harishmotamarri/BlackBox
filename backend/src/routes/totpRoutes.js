const express = require('express');
const speakeasy = require('speakeasy');

const router = express.Router();

// GET /api/totp/current
router.get('/current', (req, res) => {
  try {
    const secretKey = process.env.TOTP_SECRET || 'QFBZC3OHPK4L7MUGZO5NO6XOREWN2IBQ';

    // Generate TOTP
    const token = speakeasy.totp({
      secret: secretKey,
      encoding: 'base32'
    });

    // Generate remaining time
    const currentUnixTime = Math.floor(Date.now() / 1000);
    const remainingSeconds = 30 - (currentUnixTime % 30);

    res.json({
      otp: token,
      remainingSeconds: remainingSeconds,
      serverTimestamp: currentUnixTime
    });
  } catch (error) {
    console.error('Error in /api/totp/current:', error);
    res.status(500).json({ error: 'Failed to retrieve current TOTP code' });
  }
});

module.exports = router;
