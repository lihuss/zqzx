const db = require('./db');

async function check() {
    try {
        const [rows] = await db.query("SHOW TABLES LIKE 'consultation_reports'");
        console.log('Result:', rows);
    } catch(e) {
        console.error(e);
    }
    process.exit();
}
check();
