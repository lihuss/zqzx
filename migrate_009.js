const db = require('./db');

async function migrate() {
    try {
        console.log('Starting migration 009...');
        
        // Add title column
        try {
            await db.query(`ALTER TABLE consultation_posts ADD COLUMN title VARCHAR(255) DEFAULT NULL`);
            console.log('Added title column');
        } catch (e) {
            if (!e.message.includes("Duplicate column")) console.error(e);
        }

        // Add type column
        try {
            await db.query(`ALTER TABLE consultation_posts ADD COLUMN type ENUM('question', 'answer', 'article') DEFAULT 'question'`);
            console.log('Added type column');
        } catch (e) {
             if (!e.message.includes("Duplicate column")) console.error(e);
        }

        // Add parent_id column for answers
        try {
            await db.query(`ALTER TABLE consultation_posts ADD COLUMN parent_id INT DEFAULT NULL`);
            console.log('Added parent_id column');
        } catch (e) {
             if (!e.message.includes("Duplicate column")) console.error(e);
        }

        console.log('Migration 009 completed.');
        process.exit(0);
    } catch (err) {
        console.error('Migration failed:', err);
        process.exit(1);
    }
}

migrate();
