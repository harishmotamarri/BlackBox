const express = require('express');
const { supabase } = require('../db/database');

const router = express.Router();

const asyncHandler = (fn) => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

// POST /api/partner/login
router.post(
    '/login',
    asyncHandler(async (req, res) => {
        const { username, password } = req.body;

        if (!username || !password) {
            const err = new Error('Username and password required');
            err.statusCode = 400;
            throw err;
        }

        const { data, error } = await supabase
            .from('partners')
            .select('*')
            .eq('username', username)
            .single();

        if (error || !data || data.password !== password) {
            const err = new Error('Invalid credentials');
            err.statusCode = 401;
            throw err;
        }

        res.json({ success: true, message: 'Login successful', partner: data.username });
    })
);

// POST /api/partner/assign-delivery
router.post(
    '/assign-delivery',
    asyncHandler(async (req, res) => {
        const {
            packetId,
            fromLocation,
            toLocation,
            packetType,
            authType,
            userDetails,
            batteryStatus,
            firmwareVersion,
            sensorData
        } = req.body;

        if (!packetId) {
            const err = new Error('Packet ID is required');
            err.statusCode = 400;
            throw err;
        }

        // Check if packet exists first
        const { data: packet, error: fetchError } = await supabase
            .from('packets')
            .select('packetid')
            .eq('packetid', packetId)
            .single();

        if (fetchError || !packet) {
            const err = new Error('Packet ID not found. ensure Admin has registered it.');
            err.statusCode = 404;
            throw err;
        }

        // Update with delivery details
        const { error: updateError } = await supabase
            .from('packets')
            .update({
                from_location: fromLocation,
                to_location: toLocation,
                packet_type: packetType,
                auth_type: authType,
                user_details: userDetails,
                battery_status: batteryStatus || '100%',
                firmware_version: firmwareVersion || 'v1.0.0',
                sensor_data: sensorData || '{"temp": 25, "humidity": 50}',
                in_transit: true,  // Mark as in transit once assigned
                is_active: true
            })
            .eq('packetid', packetId);

        if (updateError) {
            console.error('Update error:', updateError);
            const err = new Error('Failed to assign delivery details');
            err.statusCode = 500;
            throw err;
        }

        res.json({ success: true, message: 'Delivery assigned successfully' });
    })
);

// POST /api/partner/status
// Restricted view for partners
router.post(
    '/status',
    asyncHandler(async (req, res) => {
        const { packetId } = req.body;

        if (!packetId) {
            const err = new Error('Packet ID required');
            err.statusCode = 400;
            throw err;
        }

        const { data, error } = await supabase
            .from('packets')
            .select('*')
            .eq('packetid', packetId)
            .single();

        if (error || !data) {
            const err = new Error('Packet not found');
            err.statusCode = 404;
            throw err;
        }

        // Filter out sensitive technician fields if any (e.g., firmware_version could be hidden)
        // For now, we return most relevant logistics data
        const safeData = {
            packetId: data.packetid,
            status: data.status,
            batteryStatus: data.battery_status,
            fromLocation: data.from_location,
            toLocation: data.to_location,
            userDetails: data.user_details,
            inTransit: data.in_transit,
            updatedAt: data.updated_at
        };

        res.json({ success: true, data: safeData });
    })
);

module.exports = router;
