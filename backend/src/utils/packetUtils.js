const { supabase } = require('../db/database');

const ADDED_AUTO_LOCK_DELAY_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Checks if a packet is UNLOCKED and if it has been unlocked for more than 5 minutes.
 * If so, updates status to LOCKED.
 * @param {object} packet The packet data from Supabase
 * @returns {Promise<object>} The updated packet data or the original if no change
 */
async function ensureLockTimeout(packet) {
    if (!packet || packet.status !== 'UNLOCKED') return packet;

    // Use updated_at to determine when it was last changed (to UNLOCKED)
    const lastUpdate = new Date(packet.updated_at || Date.now()).getTime();
    const now = Date.now();

    if (now - lastUpdate >= ADDED_AUTO_LOCK_DELAY_MS) {
        console.log(`Auto-lock triggered for packet ${packet.packetid || packet.packetId} via lazy check.`);
        const { data, error } = await supabase
            .from('packets')
            .update({ status: 'LOCKED', attempts: 0 })
            .eq('packetid', packet.packetid || packet.packetId)
            .eq('status', 'UNLOCKED')
            .select()
            .single();

        if (error) {
            console.error(`Lazy auto-lock failed for ${packet.packetid || packet.packetId}:`, error);
            return packet;
        }
        return data || packet;
    }

    return packet;
}

module.exports = { ensureLockTimeout, ADDED_AUTO_LOCK_DELAY_MS };
