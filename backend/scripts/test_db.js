const { supabase } = require('../src/db/database');

async function testConnection() {
    console.log('Testing Supabase UPDATE...');

    // 1. Get a packet
    const { data: packets, error: selectError } = await supabase
        .from('packets')
        .select('*')
        .limit(1);

    if (selectError) {
        console.error('Select Error:', selectError);
        return;
    }

    if (!packets || packets.length === 0) {
        console.log('No packets found to test update on.');
        return;
    }

    const packet = packets[0];
    console.log('Found packet:', packet.packetId);

    // 2. Try UPDATE
    const { error: updateError } = await supabase
        .from('packets')
        .update({ attempts: 99 })
        .eq('packetId', packet.packetId);

    if (updateError) {
        console.error('Update Error:', updateError);
    } else {
        console.log('Update SUCCEEDED!');
    }
}

testConnection();
