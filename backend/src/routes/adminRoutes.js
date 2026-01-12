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
        const { packetId } = req.body;

        if (!packetId || String(packetId).trim() === '') {
            const err = new Error('Packet ID required');
            err.statusCode = 400;
            throw err;
        }

        // Insert new packet with default status 'LOCKED'
        const { error } = await supabase
            .from('packets')
            .insert([{ packetid: packetId.trim(), status: 'LOCKED', attempts: 0 }]);

        if (error) {
            console.error('Supabase register error:', error);
            // specific constraint error?
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

module.exports = router;
