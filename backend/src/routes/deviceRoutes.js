const express = require('express');
const { supabase } = require('../db/database');

const router = express.Router();

const asyncHandler = (fn) => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

// POST /api/device/register
// Registers or verifies ESP32 hardware association with a packet
router.post(
    '/register',
    asyncHandler(async (req, res) => {
        const deviceId = req.body.deviceId;
        
        if (!deviceId) {
            return res.status(400).json({ success: false, error: 'Device ID is required' });
        }

        const { data: packet, error } = await supabase
            .from('packets')
            .select('*')
            .eq('deviceid', deviceId)
            .single();

        if (error || !packet) {
            return res.status(404).json({ success: false, error: 'Packet not found' });
        }

        // Update last seen and firmware version if sent
        const updateData = { last_seen: new Date().toISOString() };
        if (req.body.firmwareVersion || req.body.firmware_version) {
            updateData.firmware_version = req.body.firmwareVersion || req.body.firmware_version;
        }

        await supabase
            .from('packets')
            .update(updateData)
            .eq('packetid', packet.packetid);

        res.json({
            success: true,
            packetId: packet.packetid,
            status: packet.status
        });
    })
);

// POST /api/device/heartbeat
// Updates packet telemetry (battery, location, sensor data, and status)
router.post(
    '/heartbeat',
    asyncHandler(async (req, res) => {
        const packetId = req.body.packetId || req.body.packetid || req.body.deviceId || req.body.device_id;
        
        if (!packetId) {
            return res.status(400).json({ success: false, error: 'Packet ID or Device ID is required' });
        }

        // Verify packet exists
        const { data: packet, error } = await supabase
            .from('packets')
            .select('*')
            .eq('packetid', String(packetId).trim())
            .single();

        if (error || !packet) {
            return res.status(404).json({ success: false, error: 'Packet not found' });
        }

        const updateData = {
            last_seen: new Date().toISOString()
        };

        if (req.body.status) {
            updateData.status = req.body.status;
        }
        if (req.body.battery !== undefined || req.body.battery_status !== undefined) {
            updateData.battery_status = String(req.body.battery !== undefined ? req.body.battery : req.body.battery_status);
        }
        if (req.body.lat !== undefined && req.body.lon !== undefined) {
            updateData.from_location = `Lat: ${req.body.lat}, Lon: ${req.body.lon}`;
        }
        if (req.body.sensorData || req.body.sensor_data) {
            updateData.sensor_data = req.body.sensorData || req.body.sensor_data;
        }

        const { error: updateError } = await supabase
            .from('packets')
            .update(updateData)
            .eq('packetid', packet.packetid);

        if (updateError) {
            console.error('Heartbeat update error:', updateError);
            return res.status(500).json({ success: false, error: 'Failed to update heartbeat telemetry' });
        }

        res.json({
            success: true,
            message: 'Heartbeat received successfully',
            status: packet.status
        });
    })
);

// GET /api/device/commands
// Returns the next pending command for the ESP32 device
router.get(
    '/commands',
    asyncHandler(async (req, res) => {
        const packetId = req.query.packetId || req.query.packetid || req.query.deviceId || req.query.device_id;
        
        if (!packetId) {
            return res.status(400).json({ success: false, error: 'Packet ID or Device ID is required' });
        }

        // Query oldest pending command (FIFO)
        const { data: commands, error } = await supabase
            .from('device_commands')
            .select('*')
            .eq('packet_id', String(packetId).trim())
            .eq('status', 'PENDING')
            .order('created_at', { ascending: true })
            .limit(1);

        if (error) {
            console.error('Fetch commands error:', error);
            return res.status(500).json({ success: false, error: 'Database error fetching commands' });
        }

        if (commands && commands.length > 0) {
            const nextCommand = commands[0];
            return res.json({
                commandId: nextCommand.id,
                command: nextCommand.command
            });
        }

        // Default response telling device to wait
        res.json({
            command: 'WAIT'
        });
    })
);

// POST /api/device/command-complete
// ESP32 acknowledges execution of a command (SUCCESS or FAILED)
router.post(
    '/command-complete',
    asyncHandler(async (req, res) => {
        const { commandId, status } = req.body;
        
        if (!commandId) {
            return res.status(400).json({ success: false, error: 'Command ID is required' });
        }

        const cleanStatus = String(status).toUpperCase();
        if (cleanStatus !== 'SUCCESS' && cleanStatus !== 'FAILED') {
            return res.status(400).json({ success: false, error: 'Invalid status. Must be SUCCESS or FAILED' });
        }

        // Update command status in Supabase
        const { data: updatedCommand, error: commandError } = await supabase
            .from('device_commands')
            .update({ status: cleanStatus, updated_at: new Date().toISOString() })
            .eq('id', commandId)
            .select()
            .single();

        if (commandError || !updatedCommand) {
            console.error('Update command error:', commandError);
            return res.status(404).json({ success: false, error: 'Command not found or update failed' });
        }

        res.json({
            success: true,
            message: 'Command execution acknowledged successfully'
        });
    })
);

module.exports = router;
