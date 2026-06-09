const express = require('express');
const speakeasy = require('speakeasy');
const { supabase } = require('../db/database');
const { decryptSecret, generateSecret, encryptSecret } = require('../utils/totp');

const router = express.Router();

// GET /api/totp/current
router.get('/current', async (req, res) => {
  try {
    const { packetId } = req.query;
    if (!packetId) {
      return res.status(400).json({ error: 'packetId query parameter is required' });
    }

    const { data: packet, error } = await supabase
      .from('packets')
      .select('packetid, otphash, totpSecret')
      .eq('packetid', packetId)
      .single();

    if (error || !packet) {
      return res.status(404).json({ error: 'Packet not found' });
    }

    const currentUnixTime = Math.floor(Date.now() / 1000);
    const remainingSeconds = 30 - (currentUnixTime % 30);
    const isPaired = packet.totpSecret === 'true';

    if (!isPaired) {
      return res.json({
        paired: false,
        remainingSeconds: remainingSeconds,
        packetId: packetId
      });
    }

    let secretKey;
    if (!packet.otphash) {
      // Auto-generate, encrypt, and save if not exists
      secretKey = generateSecret();
      const encryptedSecret = encryptSecret(secretKey);
      await supabase
        .from('packets')
        .update({ otphash: encryptedSecret })
        .eq('packetid', packetId);
    } else {
      secretKey = decryptSecret(packet.otphash);
    }

    // Generate TOTP
    const token = speakeasy.totp({
      secret: secretKey,
      encoding: 'base32'
    });

    res.json({
      paired: true,
      otp: token,
      remainingSeconds: remainingSeconds,
      packetId: packetId
    });
  } catch (error) {
    console.error('Error in /api/totp/current:', error);
    res.status(500).json({ error: 'Failed to retrieve current TOTP code' });
  }
});

module.exports = router;
