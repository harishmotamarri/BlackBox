const { createApp } = require('./app');
const { supabase } = require('./db/database');
const { generateSecret, encryptSecret } = require('./utils/totp');

const PORT = Number(process.env.PORT || 5000);
const HOST = process.env.HOST || '0.0.0.0';

async function runMigrations() {
  console.log('Running startup TOTP migrations...');
  try {
    const { data: packets, error } = await supabase
      .from('packets')
      .select('packetid, otphash');

    if (error) {
      console.error('Migration failed to fetch packets:', error.message);
      return;
    }

    for (const packet of packets) {
      if (!packet.otphash) {
        console.log(`Generating unique TOTP secret for packet: ${packet.packetid}`);
        const secret = generateSecret();
        const encryptedSecret = encryptSecret(secret);
        const { error: updateError } = await supabase
          .from('packets')
          .update({ otphash: encryptedSecret })
          .eq('packetid', packet.packetid);

        if (updateError) {
          console.error(`Failed to migrate packet ${packet.packetid}:`, updateError.message);
        } else {
          console.log(`Packet ${packet.packetid} successfully migrated.`);
        }
      }
    }
    console.log('TOTP migrations completed.');
  } catch (err) {
    console.error('Error during TOTP migration:', err);
  }
}

const app = createApp();

app.listen(PORT, HOST, () => {
  console.log(`BlackBox Server running on http://localhost:${PORT}`);
  runMigrations();
});
