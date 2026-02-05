const db = require('./db');
const migrationName = '010_consultation_reports';

async function runMigration() {
    console.log(`Starting migration: ${migrationName}`);
    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        // Check if table exists
        const [tables] = await connection.query("SHOW TABLES LIKE 'consultation_reports'");
        if (tables.length === 0) {
            await connection.query(`
                CREATE TABLE consultation_reports (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    post_id INT NOT NULL,
                    reporter_id INT,
                    reason VARCHAR(255),
                    status ENUM('pending', 'resolved', 'dismissed') DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP NULL,
                    FOREIGN KEY (post_id) REFERENCES consultation_posts(id) ON DELETE CASCADE,
                    FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE SET NULL
                )
            `);
            console.log('Created consultation_reports table.');
        } else {
            console.log('consultation_reports table already exists.');
        }

        await connection.commit();
        console.log(`Migration ${migrationName} completed successfully.`);
    } catch (error) {
        await connection.rollback();
        console.error(`Migration ${migrationName} failed:`, error);
    } finally {
        connection.release();
        process.exit();
    }
}

runMigration();
