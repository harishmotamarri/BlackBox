const { supabase } = require('./backend/src/db/database');

async function checkSchema() {
    const { data, error } = await supabase
        .from('packets')
        .select('*')
        .limit(1);

    if (error) {
        console.error('Error fetching packet:', error);
        return;
    }

    if (data && data.length > 0) {
        console.log('Columns in packets table:', Object.keys(data[0]));
    } else {
        console.log('No packets found to determine columns.');
    }
    process.exit(0);
}

checkSchema();
