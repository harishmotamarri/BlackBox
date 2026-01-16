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
        const { packetId, registeredNumber } = req.body;

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

        // Insert new packet
        const { error } = await supabase
            .from('packets')
            .insert([{
                packetid: packetId.trim(),
                registered_number: registeredNumber.trim(),
                status: 'LOCKED',
                attempts: 0,
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

        const { error } = await supabase
            .from('packets')
            .delete()
            .eq('packetid', packetId.trim());

        if (error) {
            console.error('Supabase delete error:', error);
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

        // Determine OTP status
        let otpStatus = 'None';
        if (data.current_otp) {
            if (data.otpexpiresat && Date.now() < Number(data.otpexpiresat)) {
                otpStatus = 'Active';
            } else {
                otpStatus = 'Expired';
            }
        }

        res.json({
            success: true,
            data: {
                packetId: data.packetid,
                registeredNumber: data.registered_number,
                status: data.status,
                attempts: data.attempts || 0,
                otpStatus,
                otp: data.current_otp,
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

module.exports = router;
