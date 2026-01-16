
const BASE_URL = 'http://localhost:5000/api/admin';

async function test() {
    console.log('Starting verification...');

    const packetId = 'TEST-PKT-DEL-' + Date.now();
    const registeredNumber = '123456';

    // 1. Register Packet
    console.log(`\n1. Registering packet: ${packetId}`);
    try {
        const res = await fetch(`${BASE_URL}/register-packet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ packetId, registeredNumber })
        });
        const data = await res.json();
        console.log(`Status: ${res.status}`);
        console.log('Response:', data);
        if (!res.ok) throw new Error('Registration failed');
    } catch (e) {
        console.error('Registration error:', e.message);
        return;
    }

    // 2. Remove Packet
    console.log(`\n2. Removing packet: ${packetId}`);
    try {
        const res = await fetch(`${BASE_URL}/remove-packet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ packetId })
        });
        const data = await res.json();
        console.log(`Status: ${res.status}`);
        console.log('Response:', data);
        if (!res.ok) throw new Error('Removal failed');
    } catch (e) {
        console.error('Removal error:', e.message);
        return;
    }

    // 3. Try to Remove Packet Again (Should fail)
    console.log(`\n3. Verifying removal (trying to remove again)`);
    try {
        const res = await fetch(`${BASE_URL}/remove-packet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ packetId })
        });
        const data = await res.json();
        console.log(`Status: ${res.status} (Expected 404 or similar)`);
        console.log('Response:', data);
        if (res.status === 404) {
            console.log('SUCCESS: Packet not found as expected.');
        } else {
            console.log('WARNING: Unexpected status code.');
        }
    } catch (e) {
        console.log('Fetch error (might be expected):', e.message);
    }
}

test();
