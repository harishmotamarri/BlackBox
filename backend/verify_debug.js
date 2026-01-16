
const BASE_URL = 'http://localhost:5000/api/admin';

async function test() {
    console.log('Starting Extended Feature Verification...');

    const packet = {
        packetId: 'EXT-DEBUG-' + Date.now(),
        registeredNumber: '9988776655',
        fromLocation: 'Warehouse A',
        // ... other fields
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
        console.log('Status:', res.status);
        console.log('Response Body:', JSON.stringify(data, null, 2));

        if (!res.ok) throw new Error(data.message || 'Registration failed');
    } catch (e) {
        console.error('Registration error:', e.message);
    }
}

test();
