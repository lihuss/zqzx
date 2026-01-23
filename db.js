const mysql = require('mysql2');

// 创建连接池 (比单次连接更高效，适合网站)
const pool = mysql.createPool({
    host: '112.74.54.5',      // 数据库地址
    user: 'root',           // 数据库账号 (通常是 root)
    password: 'Zqzx2025@Start!',       // 【注意】这里填你的数据库密码，如果是phpStudy通常是root
    database: 'zz_memory_2025',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// 把 promise 版本的连接池导出，方便使用 await
module.exports = pool.promise();