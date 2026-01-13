-- =====================================================
-- 邀请制注册系统数据库迁移脚本
-- 针对: zz_memory_2025 数据库
-- =====================================================

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    campus VARCHAR(50),              -- 校区：主校区/大旺校区
    school_type VARCHAR(20),         -- 初中/高中
    graduation_year YEAR,            -- 届（2025, 2024等）
    class_name VARCHAR(50),          -- 班级
    is_admin BOOLEAN DEFAULT FALSE,  -- 是否管理员
    invited_by INT,                  -- 邀请人ID
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL
);

-- 邀请码表
CREATE TABLE IF NOT EXISTS invite_codes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    code VARCHAR(16) UNIQUE NOT NULL,
    created_by INT,                  -- 生成者ID（NULL表示系统/管理员生成）
    used_by INT,                     -- 使用者ID（NULL表示未使用）
    used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (used_by) REFERENCES users(id) ON DELETE SET NULL
);

-- 修改 posts 表添加 user_id 字段（如果不存在则执行）
ALTER TABLE posts ADD COLUMN user_id INT AFTER class_id;
ALTER TABLE posts ADD FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

-- 修改 comments 表添加 user_id 字段（如果不存在则执行）
ALTER TABLE comments ADD COLUMN user_id INT AFTER post_id;
ALTER TABLE comments ADD FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

-- =====================================================
-- 初始邀请码（可由管理员在数据库中手动添加）
-- 示例：INSERT INTO invite_codes (code) VALUES ('ZQZX2025ADMIN01');
-- =====================================================

-- 举报表
CREATE TABLE IF NOT EXISTS reports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    post_id INT NOT NULL,
    reporter_id INT,
    reason VARCHAR(255),
    status ENUM('pending', 'resolved', 'dismissed') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE SET NULL
);
