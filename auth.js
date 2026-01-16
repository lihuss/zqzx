const bcrypt = require('bcrypt');
const db = require('./db');

// 生成随机邀请码
function generateInviteCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 避免混淆的字符
    let code = 'ZQZX';
    for (let i = 0; i < 8; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

// 为新用户生成3个邀请码
async function generateInviteCodesForUser(userId) {
    const codes = [];
    for (let i = 0; i < 3; i++) {
        const code = generateInviteCode();
        await db.query('INSERT INTO invite_codes (code, created_by) VALUES (?, ?)', [code, userId]);
        codes.push(code);
    }
    return codes;
}

// 验证邀请码
async function validateInviteCode(code) {
    const [rows] = await db.query(
        'SELECT * FROM invite_codes WHERE code = ? AND used_by IS NULL',
        [code]
    );
    return rows.length > 0 ? rows[0] : null;
}

// 使用邀请码
async function useInviteCode(code, userId) {
    await db.query(
        'UPDATE invite_codes SET used_by = ?, used_at = NOW() WHERE code = ?',
        [userId, code]
    );
}

// 注册用户
async function registerUser(userData) {
    const { username, password, campus, schoolType, graduationYear, className, invitedBy } = userData;

    // 加密密码
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // 插入用户
    const [result] = await db.query(
        `INSERT INTO users (username, password_hash, campus, school_type, graduation_year, class_name, invited_by) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [username, passwordHash, campus, schoolType, graduationYear, className, invitedBy]
    );

    return result.insertId;
}

// 验证登录
async function authenticateUser(username, password) {
    const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) return null;

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    return match ? user : null;
}

// 通过ID获取用户
async function getUserById(id) {
    const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]);
    return rows.length > 0 ? rows[0] : null;
}

// 获取用户的邀请码
async function getUserInviteCodes(userId) {
    const [rows] = await db.query(
        `SELECT ic.*, u.username as used_by_username 
         FROM invite_codes ic 
         LEFT JOIN users u ON ic.used_by = u.id 
         WHERE ic.created_by = ?
         ORDER BY ic.created_at DESC`,
        [userId]
    );
    return rows;
}

// 检查用户名是否存在
async function usernameExists(username) {
    const [rows] = await db.query('SELECT id FROM users WHERE username = ?', [username]);
    return rows.length > 0;
}

// 管理员生成邀请码（无需 created_by）
async function adminGenerateInviteCode() {
    const code = generateInviteCode();
    await db.query('INSERT INTO invite_codes (code) VALUES (?)', [code]);
    return code;
}

// 获取所有未使用的系统邀请码（管理员用）
async function getSystemInviteCodes() {
    const [rows] = await db.query(
        'SELECT * FROM invite_codes WHERE created_by IS NULL ORDER BY created_at DESC'
    );
    return rows;
}

module.exports = {
    generateInviteCode,
    generateInviteCodesForUser,
    validateInviteCode,
    useInviteCode,
    registerUser,
    authenticateUser,
    getUserById,
    getUserInviteCodes,
    usernameExists,
    adminGenerateInviteCode,
    getSystemInviteCodes
};
