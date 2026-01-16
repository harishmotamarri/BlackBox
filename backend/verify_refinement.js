
const BASE_URL = 'http://localhost:5000/api/admin';

async function test() {
    console.log('Starting Refined Feature Verification...');

    const packet = {
        packetId: 'REF-TEST-' + Date.now(),
        registeredNumber: '1122334455'
        // No extended fields
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

        console.log('Status Retrieved:');
        console.log(`- Packet ID: ${d.packetId}`);
        console.log(`- Is Active: ${d.isActive} (Expect: true)`);
        console.log(`- In Transit: ${d.inTransit} (Expect: false)`);
        console.log(`- Packet Type: ${d.packetType} (Expect: Standard)`); // Default from DB?
        console.log(`- Auth Type: ${d.authType} (Expect: OTP)`); // Default from DB?
        console.log(`- From Location: ${d.fromLocation}`);

        if (d.isActive === true) {
            console.log('SUCCESS: Defaults applied correctly.');
        } else {
            console.error('FAILURE: Defaults incorrect.');
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
