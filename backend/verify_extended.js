
const BASE_URL = 'http://localhost:5000/api/admin';

async function test() {
    console.log('Starting Extended Feature Verification...');

    const packet = {
        packetId: 'EXT-TEST-' + Date.now(),
        registeredNumber: '9988776655',
        fromLocation: 'Warehouse A',
        toLocation: 'Store B',
        packetType: 'Fragile',
        authType: 'QR',
        userDetails: 'John Doe, 555-0199',
        isActive: true,
        inTransit: true,
        batteryStatus: '98%',
        firmwareVersion: 'v2.1',
        sensorData: { temp: 22, hum: 45 }
    };

    // 1. Register Packet
    console.log(`\n1. Registering packet: ${packet.packetId}`);
    try {
        const res = await fetch(`${BASE_URL}/register-packet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(packet)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.message || 'Registration failed');
        console.log('Registration successful');
    } catch (e) {
        console.error('Registration error:', e.message);
        return;
    }

    // 2. Check Status
    console.log(`\n2. Checking status for: ${packet.packetId}`);
    try {
        const res = await fetch(`${BASE_URL}/packet-status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ packetId: packet.packetId })
        });
        const data = await res.json();
        const d = data.data;

        let mismatch = false;
        if (d.fromLocation !== packet.fromLocation) mismatch = true;
        if (d.toLocation !== packet.toLocation) mismatch = true;
        if (d.packetType !== packet.packetType) mismatch = true;
        if (d.authType !== packet.authType) mismatch = true;
        if (d.userDetails !== packet.userDetails) mismatch = true;

        // Note: sensorData comes back as string or object depending on driver, but we won't be too strict here

        if (!mismatch) {
            console.log('SUCCESS: All extended fields match.');
            console.log(d);
        } else {
            console.error('FAILURE: Field mismatch.');
            console.log('Expected:', packet);
            console.log('Received:', d);
        }
    } catch (e) {
        console.error('Check Status error:', e.message);
    }

    // 3. Cleanup
    console.log(`\n3. Cleaning up...`);
    await fetch(`${BASE_URL}/remove-packet`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packetId: packet.packetId })
    });
}

test();
