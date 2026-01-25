const { supabase } = require('./src/db/database');
const fs = require('fs');

async function checkSchema() {
    try {
        const { data, error } = await supabase
            .from('packets')
            .select('*')
            .limit(1);

        if (error) {
            fs.writeFileSync('schema_output.txt', 'Error: ' + JSON.stringify(error));
            process.exit(1);
        }

        if (data && data.length > 0) {
            fs.writeFileSync('schema_output.txt', 'COLUMNS: ' + Object.keys(data[0]).join(', '));
        } else {
            fs.writeFileSync('schema_output.txt', 'No packets found.');
        }
    } catch (e) {
        fs.writeFileSync('schema_output.txt', 'Exception: ' + e.message);
    }
    process.exit(0);
}

checkSchema();
