const db = require('./db');

async function checkClasses() {
    try {
        const [rows] = await db.query('SELECT id, name, full_name, created_at FROM classes WHERE name LIKE "%9班%" OR full_name LIKE "%9班%" ORDER BY full_name');
        console.log(JSON.stringify(rows, null, 2));
    } catch (err) {
        console.error(err);
    } finally {
        process.exit();
    }
}

checkClasses();
