const express = require('express');
const { supabase } = require('../db/database');

const router = express.Router();

const asyncHandler = (fn) => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

// POST /api/admin/login
router.post(
    '/login',
    asyncHandler(async (req, res) => {
        const { username, password } = req.body;

        if (!username || !password) {
            const err = new Error('Username and password required');
            err.statusCode = 400;
            throw err;
        }

        // Query Supabase for the admin
        const { data, error } = await supabase
            .from('admins')
            .select('*')
            .eq('username', username)
            .single();

        if (error || !data) {
            if (error && error.code !== 'PGRST116') {
                console.error('Supabase admin login error:', error);
            }
            const err = new Error('Invalid credentials');
            err.statusCode = 401;
            throw err;
        }

        // Compare password (plaintext for now as per demo requirements)
        if (data.password !== password) {
            const err = new Error('Invalid credentials');
            err.statusCode = 401;
            throw err;
        }

        // Success
        res.json({ success: true, message: 'Login successful' });
    })
);

// POST /api/admin/register-packet
router.post(
    '/register-packet',
    asyncHandler(async (req, res) => {
        const { packetId, registeredNumber, verificationCode } = req.body;

        if (!packetId || String(packetId).trim() === '') {
            const err = new Error('Packet ID required');
            err.statusCode = 400;
            throw err;
        }

        if (!registeredNumber || String(registeredNumber).trim() === '') {
            const err = new Error('Registered Number required');
            err.statusCode = 400;
            throw err;
        }

        if (!verificationCode || String(verificationCode).trim() === '') {
            const err = new Error('Verification Code required');
            err.statusCode = 400;
            throw err;
        }

        // Insert new packet
        const { error } = await supabase
            .from('packets')
            .insert([{
                packetid: packetId.trim(),
                registered_number: registeredNumber.trim(),
                status: 'LOCKED',
                attempts: 0,
                auth_type: '-',
                current_otp: verificationCode.trim(), // Store verification code here
                // New Fields (set to defaults or null as they are not provided by Admin)
                is_active: true,
                in_transit: false
            }]);

        if (error) {
            console.error('Supabase register error:', error);
            if (error.code === '23505') { // unique_violation
                const err = new Error('Packet ID already exists');
                err.statusCode = 409;
                throw err;
            }
            const err = new Error('Failed to register packet');
            err.statusCode = 500;
            throw err;
        }

        res.json({ success: true, message: 'Packet registered successfully' });
    })
);

// POST /api/admin/remove-packet
router.post(
    '/remove-packet',
    asyncHandler(async (req, res) => {
        const { packetId } = req.body;

        if (!packetId || String(packetId).trim() === '') {
            const err = new Error('Packet ID required');
            err.statusCode = 400;
            throw err;
        }

        // First, check if the packet exists
        const { data: existingPacket, error: fetchError } = await supabase
            .from('packets')
            .select('packetid, in_transit')
            .eq('packetid', packetId.trim())
            .single();

        if (fetchError || !existingPacket) {
            if (fetchError && fetchError.code !== 'PGRST116') {
                console.error('Supabase fetch error before delete:', fetchError);
                const err = new Error('Database error');
                err.statusCode = 500;
                throw err;
            }
            const err = new Error('Packet not found');
            err.statusCode = 404;
            throw err;
        }

        // BLOCK REMOVAL IF IN TRANSIT
        if (existingPacket.in_transit) {
            const err = new Error('Packet is currently with a partner (In Transit) and cannot be removed.');
            err.statusCode = 403;
            throw err;
        }

        const { error: deleteError } = await supabase
            .from('packets')
            .delete()
            .eq('packetid', packetId.trim());

        if (deleteError) {
            console.error('Supabase delete error:', deleteError);
            const err = new Error('Failed to remove packet');
            err.statusCode = 500;
            throw err;
        }

        res.json({ success: true, message: 'Packet removed successfully' });
    })
);

// POST /api/admin/packet-status
router.post(
    '/packet-status',
    asyncHandler(async (req, res) => {
        const { packetId } = req.body;

        if (!packetId || String(packetId).trim() === '') {
            const err = new Error('Packet ID required');
            err.statusCode = 400;
            throw err;
        }

        const { data, error } = await supabase
            .from('packets')
            .select('*')
            .eq('packetid', packetId.trim())
            .single();

        if (error || !data) {
            if (error && error.code !== 'PGRST116') {
                console.error('Supabase fetch error:', error);
                const err = new Error('Database error');
                err.statusCode = 500;
                throw err;
            }
            const err = new Error('Packet not found');
            err.statusCode = 404;
            throw err;
        }

        // Verification Code status
        let verificationCodeStatus = data.current_otp ? 'Set' : 'Not Set';

        res.json({
            success: true,
            data: {
                packetId: data.packetid,
                registeredNumber: data.registered_number,
                status: data.status,
                attempts: data.attempts || 0,
                verificationCodeStatus,
                verificationCode: data.current_otp,
                // New Fields
                isActive: data.is_active,
                inTransit: data.in_transit,
                sensorData: data.sensor_data,
                batteryStatus: data.battery_status,
                firmwareVersion: data.firmware_version,
                fromLocation: data.from_location,
                toLocation: data.to_location,
                packetType: data.packet_type,
                authType: data.auth_type,
                userDetails: data.user_details
            }
        });
    })
);

// GET /api/admin/all-packets
router.get(
    '/all-packets',
    asyncHandler(async (req, res) => {
        const { data, error } = await supabase
            .from('packets')
            .select('*');

        if (error) {
            console.error('Supabase fetch all packets error:', error);
            const err = new Error('Database error');
            err.statusCode = 500;
            throw err;
        }

        res.json({
            success: true,
            data: data
        });
    })
);

// POST /api/admin/master-lock
router.post(
    '/master-lock',
    asyncHandler(async (req, res) => {
        const { packetId } = req.body;
        if (!packetId) {
            const err = new Error('Packet ID required');
            err.statusCode = 400;
            throw err;
        }

        const { error } = await supabase
            .from('packets')
            .update({ status: 'LOCKED', attempts: 0 })
            .eq('packetid', packetId.trim());

        if (error) {
            const err = new Error('Database error');
            err.statusCode = 500;
            throw err;
        }

        res.json({ success: true, message: 'Packet Master Locked' });
    })
);

// POST /api/admin/master-unlock
router.post(
    '/master-unlock',
    asyncHandler(async (req, res) => {
        const { packetId } = req.body;
        if (!packetId) {
            const err = new Error('Packet ID required');
            err.statusCode = 400;
            throw err;
        }

        const { error } = await supabase
            .from('packets')
            .update({ status: 'UNLOCKED', attempts: 0 })
            .eq('packetid', packetId.trim());

        if (error) {
            const err = new Error('Database error');
            err.statusCode = 500;
            throw err;
        }

        res.json({ success: true, message: 'Packet Master Unlocked' });
    })
);

// POST /api/admin/update-sensors
router.post(
    '/update-sensors',
    asyncHandler(async (req, res) => {
        const { packetId, action } = req.body;
        if (!packetId || !action) {
            const err = new Error('Packet ID and action required');
            err.statusCode = 400;
            throw err;
        }

        let newSensorData = '-';
        if (action === 'recalibrate') {
            newSensorData = { status: 'recalibrated', lastCalibration: new Date().toISOString() };
        } else if (action === 'turn_off') {
            newSensorData = null; // or '-' depending on your db schema, null is usually fine for JSONB or TEXT. We'll use '-' to match existing logic
        }

        const { error } = await supabase
            .from('packets')
            .update({ sensor_data: newSensorData === null ? '-' : newSensorData })
            .eq('packetid', packetId.trim());

        if (error) {
            const err = new Error('Database error');
            err.statusCode = 500;
            throw err;
        }

        res.json({ success: true, message: 'Sensors updated successfully' });
    })
);

module.exports = router;
