const { supabase } = require('./src/db/database');

async function checkSchema() {
    const { data, error } = await supabase
        .from('packets')
        .select('*')
        .limit(1);

    if (error) {
        console.error('Error fetching packet:', error);
        process.exit(1);
    }

    if (data && data.length > 0) {
        console.log('COLUMNS:', Object.keys(data[0]).join(','));
    } else {
        console.log('No packets found.');
    }
    process.exit(0);
}

checkSchema();
