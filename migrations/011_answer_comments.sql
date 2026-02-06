-- Add updated_at column to track edits on consultation posts/answers
ALTER TABLE consultation_posts ADD COLUMN updated_at TIMESTAMP NULL;

-- Comments on answers (for discussions under each answer)
CREATE TABLE IF NOT EXISTS consultation_answer_comments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    answer_id INT NOT NULL,              -- Reference to the answer (consultation_posts with type='answer')
    user_id INT NOT NULL,                -- Comment author
    content TEXT NOT NULL,               -- Comment content
    is_anonymous TINYINT(1) DEFAULT 0,   -- Anonymous commenting option
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (answer_id) REFERENCES consultation_posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
