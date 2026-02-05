const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const moment = require('moment');
const session = require('express-session');
const db = require('./db');
const auth = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

// 配置中间件
app.set('view engine', 'ejs');
app.use(express.static('public'));

// ------------------- 请添加以下两行代码 -------------------
app.use('/lib/bootstrap', express.static(path.join(__dirname, 'node_modules/bootstrap/dist')));
app.use('/lib/fontawesome', express.static(path.join(__dirname, 'node_modules/@fortawesome/fontawesome-free')));
// --------------------------------------------------------

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 配置 Session（Cookie 保持登录30天）
app.use(session({
    secret: 'zqzx2025-memory-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30天
        httpOnly: true
    }
}));

// 将用户信息注入到所有视图
app.use(async (req, res, next) => {
    res.locals.user = null;
    if (req.session.userId) {
        try {
            const user = await auth.getUserById(req.session.userId);
            if (user) {
                // 判断是否为大学生
                if (user.school_type === '高中') {
                    const now = new Date();
                    const gradYear = parseInt(user.graduation_year);
                    // 6月9日
                    const gradDate = new Date(gradYear, 5, 9); // Month is 0-indexed: 5 = June
                    user.isCollegeStudent = now > gradDate;
                } else {
                    user.isCollegeStudent = false;
                }
            }
            res.locals.user = user;
        } catch (err) {
            console.error('获取用户信息失败:', err);
        }
    }
    next();
});

// 登录验证中间件
function requireAuth(req, res, next) {
    // 增加 !res.locals.user 判断：
    // 如果 Session 里有 ID，但在数据库没查到人（res.locals.user 为空），也视为未登录
    if (!req.session.userId || !res.locals.user) {

        // 如果 Session 还在但人没了，顺便把 Session 销毁掉，免得死循环
        if (req.session) {
            req.session.destroy();
        }

        return res.redirect('/login');
    }
    next();
}

// 管理员验证中间件
function requireAdmin(req, res, next) {
    if (!res.locals.user || !res.locals.user.is_admin) {
        return res.status(403).render('admin', { user: res.locals.user, systemCodes: [] });
    }
    next();
}

// 配置图片上传
// 生产环境：使用项目外的独立目录（不会被部署覆盖）
// 开发环境：使用项目内的 public/uploads
const UPLOADS_DIR = process.env.UPLOADS_DIR || (
    process.env.NODE_ENV === 'production'
        ? '/var/www/zqzx-uploads'  // 服务器上的独立目录
        : path.join(__dirname, 'public/uploads')  // 本地开发
);

// 确保上传目录存在
const fs = require('fs');
if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// 生产环境需要单独挂载 uploads 目录的静态服务
if (process.env.NODE_ENV === 'production') {
    app.use('/uploads', express.static(UPLOADS_DIR));
}

// ============================
// 树洞匿名ID系统
// ============================

// 加载名字列表
let anonymousNames = [];
try {
    const namesPath = path.join(__dirname, 'public/data/names.txt');
    const namesContent = fs.readFileSync(namesPath, 'utf-8');
    anonymousNames = namesContent.split('\n').map(n => n.trim()).filter(n => n.length > 0);
    console.log(`加载了 ${anonymousNames.length} 个匿名名字`);
} catch (err) {
    console.error('加载名字列表失败:', err);
    // 降级使用默认名字列表
    anonymousNames = ['Alex', 'Blake', 'Casey', 'Drew', 'Eden', 'Finn', 'Gray', 'Harper', 'Ivy', 'Jordan'];
}

// 生成确定性的匿名名字（同一帖子+同一用户始终返回相同名字）
function getAnonymousName(postId, userId, usedNames = new Set()) {
    // 使用帖子ID和用户ID生成确定性种子
    const seed = postId * 10007 + userId * 31;
    let index = Math.abs(seed) % anonymousNames.length;
    let name = anonymousNames[index];

    // 如果名字已被使用，线性探测找下一个可用的
    let attempts = 0;
    while (usedNames.has(name) && attempts < anonymousNames.length) {
        index = (index + 1) % anonymousNames.length;
        name = anonymousNames[index];
        attempts++;
    }

    return name;
}

// 为帖子中的所有用户生成唯一的匿名名字映射
function buildAnonymousNameMap(postId, postUserId, replies) {
    const userNameMap = {};
    const usedNames = new Set();

    // 收集所有参与的用户ID（包括帖主）
    const allUserIds = new Set([postUserId]);
    for (const reply of replies) {
        if (reply.user_id) {
            allUserIds.add(reply.user_id);
        }
    }

    // 为每个用户分配唯一名字（帖主优先）
    for (const userId of allUserIds) {
        const name = getAnonymousName(postId, userId, usedNames);
        userNameMap[userId] = name;
        usedNames.add(name);
    }

    return userNameMap;
}

// 解析引用格式 #ID（全局ID，支持跨帖引用）
async function parseQuotes(content, currentPostId) {
    const quotePattern = /#(\d+)/g;
    const quotes = [];
    let match;

    while ((match = quotePattern.exec(content)) !== null) {
        const messageId = parseInt(match[1], 10);
        try {
            // 在统一消息表中查找
            const [msgResults] = await db.query(
                'SELECT id, parent_id, content FROM treehole_messages WHERE id = ?',
                [messageId]
            );
            if (msgResults.length > 0) {
                const quotedMsg = msgResults[0];
                // 判断是否同帖：如果是主帖(parent_id=null)则看id，如果是回复则看parent_id
                const targetPostId = quotedMsg.parent_id || quotedMsg.id;
                quotes.push({
                    id: messageId,
                    content: quotedMsg.content.length > 80
                        ? quotedMsg.content.substring(0, 80) + '...'
                        : quotedMsg.content,
                    isSameThread: targetPostId == currentPostId,
                    targetPostId: targetPostId
                });
            }
        } catch (err) {
            console.error('解析引用失败:', err);
        }
    }

    return quotes;
}

// --- 认证路由 ---

// 登录页
app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/treehole');
    }
    res.render('login', { error: null, success: req.query.registered ? '注册成功，请登录！' : null });
});

// 处理登录
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await auth.authenticateUser(username, password);

        if (!user) {
            return res.render('login', { error: '用户名或密码错误', success: null });
        }

        req.session.userId = user.id;
        res.redirect('/treehole');
    } catch (err) {
        console.error('登录失败:', err);
        res.render('login', { error: '登录失败，请稍后重试', success: null });
    }
});

// 注册页
app.get('/register', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/treehole');
    }
    res.render('register', { error: null, inviteCode: req.query.code || '', formData: {} });
});

// 处理注册
app.post('/register', async (req, res) => {
    try {
        const { inviteCode, username, password, confirmPassword, campus, schoolType, graduationYear, className } = req.body;
        const formData = { username, campus, schoolType, graduationYear, className };

        // 验证密码
        if (password !== confirmPassword) {
            return res.render('register', { error: '两次输入的密码不一致', inviteCode, formData });
        }

        if (password.length < 6) {
            return res.render('register', { error: '密码至少需要6个字符', inviteCode, formData });
        }

        // 验证用户名
        if (username.length < 2 || username.length > 20) {
            return res.render('register', { error: '用户名需要2-20个字符', inviteCode, formData });
        }

        if (await auth.usernameExists(username)) {
            return res.render('register', { error: '用户名已被占用', inviteCode, formData });
        }

        // 验证邀请码
        const invite = await auth.validateInviteCode(inviteCode.toUpperCase());
        if (!invite) {
            return res.render('register', { error: '邀请码无效或已被使用', inviteCode, formData });
        }

        // 注册用户
        const userId = await auth.registerUser({
            username,
            password,
            campus,
            schoolType,
            graduationYear,
            className,
            invitedBy: invite.created_by
        });

        // 使用邀请码
        await auth.useInviteCode(inviteCode.toUpperCase(), userId);

        // 为新用户生成3个邀请码
        await auth.generateInviteCodesForUser(userId);

        res.redirect('/login?registered=1');
    } catch (err) {
        console.error('注册失败:', err);
        res.render('register', { error: '注册失败，请稍后重试', inviteCode: req.body.inviteCode, formData: req.body });
    }
});

// 退出登录
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});


// --- 个人主页 ---
app.get('/profile', requireAuth, async (req, res) => {
    try {
        const codes = await auth.getUserInviteCodes(req.session.userId);
        res.render('profile', { user: res.locals.user, codes });
    } catch (err) {
        console.error('获取个人主页数据失败:', err);
        res.render('profile', { user: res.locals.user, codes: [] });
    }
});

app.post('/profile/update', requireAuth, async (req, res) => {
    try {
        const { university } = req.body;
        // 仅允许大学生更新大学信息
        if (res.locals.user.isCollegeStudent) {
            await db.query('UPDATE users SET university = ? WHERE id = ?', [university ? university.trim() : null, req.session.userId]);
        }
        res.redirect('/profile');
    } catch (err) {
        console.error('更新个人信息失败:', err);
        res.redirect('/profile');
    }
});

// --- 管理员路由 ---

// 获取管理面板数据（容错处理，部分表可能不存在）
async function getAdminData() {
    let systemCodes = [];
    let classes = [];
    let reports = [];

    // 获取系统邀请码
    try {
        systemCodes = await auth.getSystemInviteCodes();
    } catch (err) {
        console.error('获取邀请码失败:', err.message);
    }

    // 获取班级列表（简单查询，不依赖其他表）
    try {
        const [rows] = await db.query('SELECT * FROM classes ORDER BY created_at DESC');
        classes = rows;

        // 尝试获取每个班级的帖子数
        for (let cls of classes) {
            try {
                const [countResult] = await db.query(
                    'SELECT COUNT(*) as count FROM posts WHERE class_id = ?',
                    [cls.id]
                );
                cls.post_count = countResult[0].count;
            } catch (e) {
                cls.post_count = 0;
            }
        }
    } catch (err) {
        console.error('获取班级列表失败:', err.message);
    }

    // 获取举报列表（表可能不存在）
    // 获取举报列表（合并 班级圈 和 树洞）
    try {
        // 1. 班级圈举报
        const [classReports] = await db.query(`
            SELECT r.id, r.post_id, r.reporter_id, r.reason, r.status, r.created_at, 
                   p.content as post_content, p.class_id, u.username as reporter_name,
                   'class' as type
            FROM reports r
            LEFT JOIN posts p ON r.post_id = p.id
            LEFT JOIN users u ON r.reporter_id = u.id
            ORDER BY r.created_at DESC
        `);

        // 2. 树洞举报
        let treeholeReports = [];
        try {
            const [trRows] = await db.query(`
                SELECT tr.id, tr.message_id as post_id, tr.reporter_id, tr.reason, tr.status, tr.created_at, 
                       tm.content as post_content, 0 as class_id, u.username as reporter_name,
                       'treehole' as type
                FROM treehole_reports tr
                LEFT JOIN treehole_messages tm ON tr.message_id = tm.id
                LEFT JOIN users u ON tr.reporter_id = u.id
                ORDER BY tr.created_at DESC
            `);
            treeholeReports = trRows;
        } catch (e) {
            // 表可能不存在，忽略
        }

        // 3. 咨询专区举报
        let consultationReports = [];
        try {
            const [crRows] = await db.query(`
                SELECT cr.id, cr.post_id, cr.reporter_id, cr.reason, cr.status, cr.created_at, 
                       cp.content as post_content, cp.title, 0 as class_id, u.username as reporter_name,
                       'consultation' as type
                FROM consultation_reports cr
                LEFT JOIN consultation_posts cp ON cr.post_id = cp.id
                LEFT JOIN users u ON cr.reporter_id = u.id
                ORDER BY cr.created_at DESC
            `);
            consultationReports = crRows;
        } catch (e) {
             console.error('获取咨询举报失败', e);
        }

        // 合并并按时间排序
        reports = [...classReports, ...treeholeReports, ...consultationReports].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    } catch (err) {
        console.error('获取举报列表失败:', err.message);
    }

    return { systemCodes, classes, reports };
}

// 管理面板
app.get('/admin', requireAuth, requireAdmin, async (req, res) => {
    try {
        const data = await getAdminData();
        res.render('admin', { user: res.locals.user, ...data, newCodes: null });
    } catch (err) {
        console.error('获取管理数据失败:', err);
        res.render('admin', { user: res.locals.user, systemCodes: [], classes: [], reports: [], newCodes: null });
    }
});

// 生成系统邀请码
app.post('/admin/generate-code', requireAuth, requireAdmin, async (req, res) => {
    try {
        const count = parseInt(req.body.count) || 1;
        const newCodes = [];

        for (let i = 0; i < Math.min(count, 10); i++) {
            const code = await auth.adminGenerateInviteCode();
            newCodes.push(code);
        }

        const data = await getAdminData();
        res.render('admin', { user: res.locals.user, ...data, newCodes });
    } catch (err) {
        console.error('生成邀请码失败:', err);
        res.redirect('/admin');
    }
});

// 创建班级（管理员）
app.post('/admin/create-class', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { year, className } = req.body;
        const fullName = `${year}届 ${className.trim()}`;

        const [existing] = await db.query('SELECT * FROM classes WHERE full_name = ?', [fullName]);
        if (existing.length === 0) {
            await db.query('INSERT INTO classes (name, full_name) VALUES (?, ?)', [className.trim(), fullName]);
        }
        res.redirect('/admin');
    } catch (err) {
        console.error('创建班级失败:', err);
        res.redirect('/admin');
    }
});

// 删除班级（管理员）
app.post('/admin/delete-class/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const classId = req.params.id;
        // 删除关联的评论、帖子，然后删除班级
        await db.query('DELETE FROM comments WHERE post_id IN (SELECT id FROM posts WHERE class_id = ?)', [classId]);
        await db.query('DELETE FROM posts WHERE class_id = ?', [classId]);
        await db.query('DELETE FROM classes WHERE id = ?', [classId]);
        res.redirect('/admin');
    } catch (err) {
        console.error('删除班级失败:', err);
        res.redirect('/admin');
    }
});

// 处理举报 - 删除帖子
app.post('/admin/report/:id/delete-post', requireAuth, requireAdmin, async (req, res) => {
    try {
        const reportId = req.params.id;

        // 获取举报信息
        const [reports] = await db.query('SELECT * FROM reports WHERE id = ?', [reportId]);
        if (reports.length > 0) {
            const postId = reports[0].post_id;
            // 删除帖子及其评论
            await db.query('DELETE FROM comments WHERE post_id = ?', [postId]);
            await db.query('DELETE FROM posts WHERE id = ?', [postId]);
            // 更新举报状态
            await db.query('UPDATE reports SET status = "resolved", resolved_at = NOW() WHERE id = ?', [reportId]);
        }
        res.redirect('/admin');
    } catch (err) {
        console.error('处理举报失败:', err);
        res.redirect('/admin');
    }
});

// 处理举报 - 驳回
app.post('/admin/report/:id/dismiss', requireAuth, requireAdmin, async (req, res) => {
    try {
        await db.query('UPDATE reports SET status = "dismissed", resolved_at = NOW() WHERE id = ?', [req.params.id]);
        res.redirect('/admin');
    } catch (err) {
        console.error('驳回举报失败:', err);
        res.redirect('/admin');
    }
});

// 处理树洞举报 - 删除帖子/回复
app.post('/admin/report/treehole/:id/delete-post', requireAuth, requireAdmin, async (req, res) => {
    try {
        const reportId = req.params.id;
        const [reports] = await db.query('SELECT * FROM treehole_reports WHERE id = ?', [reportId]);

        if (reports.length > 0) {
            const messageId = reports[0].message_id;

            // 删除树洞消息（及其子回复 - 需要根据具体外键策略，这里手动删除以防万一）
            // 先删回复
            await db.query('DELETE FROM treehole_messages WHERE parent_id = ?', [messageId]);
            // 再删本体
            await db.query('DELETE FROM treehole_messages WHERE id = ?', [messageId]);

            // 更新举报状态
            await db.query('UPDATE treehole_reports SET status = "resolved", resolved_at = NOW() WHERE id = ?', [reportId]);
        }
        res.redirect('/admin');
    } catch (err) {
        console.error('处理树洞举报失败:', err);
        res.redirect('/admin');
    }
});

// 处理树洞举报 - 驳回
app.post('/admin/report/treehole/:id/dismiss', requireAuth, requireAdmin, async (req, res) => {
    try {
        await db.query('UPDATE treehole_reports SET status = "dismissed", resolved_at = NOW() WHERE id = ?', [req.params.id]);
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.redirect('/admin');
    }
});

// 处理咨询举报 - 删除帖子
app.post('/admin/report/consultation/:id/delete-post', requireAuth, requireAdmin, async (req, res) => {
    try {
        const reportId = req.params.id;
        const [reports] = await db.query('SELECT * FROM consultation_reports WHERE id = ?', [reportId]);

        if (reports.length > 0) {
            const postId = reports[0].post_id;
            
            await db.query('DELETE FROM consultation_posts WHERE id = ?', [postId]);

            // Mark report resolved
            await db.query('UPDATE consultation_reports SET status = "resolved", resolved_at = NOW() WHERE id = ?', [reportId]);
        }
        res.redirect('/admin');
    } catch (err) {
        console.error('处理咨询举报失败:', err);
        res.redirect('/admin');
    }
});

// 处理咨询举报 - 驳回
app.post('/admin/report/consultation/:id/dismiss', requireAuth, requireAdmin, async (req, res) => {
    try {
        await db.query('UPDATE consultation_reports SET status = "dismissed", resolved_at = NOW() WHERE id = ?', [req.params.id]);
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.redirect('/admin');
    }
});

// --- 原有路由 ---

// 1. 封面页
app.get('/', (req, res) => {
    res.render('index');
});

// 2. 班级大厅（需要登录）
app.get('/hall', requireAuth, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM classes ORDER BY created_at DESC');
        res.render('hall', { classes: rows });
    } catch (err) {
        console.error(err);
        res.status(500).send("数据库连接失败，请检查db.js密码配置");
    }
});

// 开通班级
app.post('/create-class', requireAuth, async (req, res) => {
    const className = req.body.className.trim();
    if (!className) return res.redirect('/hall');

    const fullName = `2025届 ${className}`;

    try {
        const [existing] = await db.query('SELECT * FROM classes WHERE full_name = ?', [fullName]);

        if (existing.length === 0) {
            await db.query('INSERT INTO classes (name, full_name) VALUES (?, ?)', [className, fullName]);
        }
        res.redirect('/hall');
    } catch (err) {
        console.log(err);
        res.redirect('/hall');
    }
});

// 3. 班级详情页
app.get('/class/:id', requireAuth, async (req, res) => {
    try {
        const classId = req.params.id;

        const [classRows] = await db.query('SELECT * FROM classes WHERE id = ?', [classId]);
        if (classRows.length === 0) return res.redirect('/hall');
        const currentClass = classRows[0];

        // 获取帖子（容错处理）
        let posts = [];
        try {
            // 尝试带 user_id 的查询
            const [rows] = await db.query(`
                SELECT p.*, u.username as author_name 
                FROM posts p 
                LEFT JOIN users u ON p.user_id = u.id 
                WHERE p.class_id = ? 
                ORDER BY p.created_at DESC
            `, [classId]);
            posts = rows;
        } catch (err) {
            // 如果失败，使用简单查询
            console.error('帖子查询失败，使用简单查询:', err.message);
            const [rows] = await db.query('SELECT * FROM posts WHERE class_id = ? ORDER BY created_at DESC', [classId]);
            posts = rows.map(p => ({ ...p, author_name: null }));
        }

        // 获取评论（容错处理）
        for (let post of posts) {
            try {
                const [comments] = await db.query(`
                    SELECT c.*, u.username as author_name 
                    FROM comments c 
                    LEFT JOIN users u ON c.user_id = u.id 
                    WHERE c.post_id = ? 
                    ORDER BY c.created_at ASC
                `, [post.id]);
                post.comments = comments;
            } catch (err) {
                // 简单查询
                try {
                    const [comments] = await db.query('SELECT * FROM comments WHERE post_id = ? ORDER BY created_at ASC', [post.id]);
                    post.comments = comments.map(c => ({ ...c, author_name: null }));
                } catch (e) {
                    post.comments = [];
                }
            }

            // 检查当前用户是否已点赞（表可能不存在）
            try {
                const [likeCheck] = await db.query(
                    'SELECT id FROM post_likes WHERE post_id = ? AND user_id = ?',
                    [post.id, req.session.userId]
                );
                post.userLiked = likeCheck.length > 0;
            } catch (likeErr) {
                post.userLiked = false;
            }
        }

        res.render('class', { currentClass, posts, moment });
    } catch (err) {
        console.error('班级页面加载失败:', err);
        res.status(500).send(`加载失败: ${err.message}`);
    }
});

// 发布帖子（支持匿名）
app.post('/class/:id/post', requireAuth, upload.array('image', 9), async (req, res) => {
    try {
        const classId = req.params.id;
        const content = req.body.content;
        const userId = req.session.userId;
        const isAnonymous = req.body.anonymous === 'on' ? 1 : 0;
        let image = '';
        if (req.files && req.files.length > 0) {
            const images = req.files.map(file => '/uploads/' + file.filename);
            image = JSON.stringify(images);
        }

        await db.query(
            'INSERT INTO posts (class_id, user_id, content, image, is_anonymous) VALUES (?, ?, ?, ?, ?)',
            [classId, userId, content, image, isAnonymous]
        );
        res.redirect(`/class/${classId}`);
    } catch (err) {
        console.log(err);
        res.send("发布失败");
    }
});

// 点赞（AJAX，防止重复）
app.post('/post/:id/like', requireAuth, async (req, res) => {
    try {
        const postId = req.params.id;
        const userId = req.session.userId;

        // 检查是否已点赞
        const [existing] = await db.query(
            'SELECT id FROM post_likes WHERE post_id = ? AND user_id = ?',
            [postId, userId]
        );

        let liked = false;
        let newCount = 0;

        if (existing.length === 0) {
            // 添加点赞
            await db.query('INSERT INTO post_likes (post_id, user_id) VALUES (?, ?)', [postId, userId]);
            await db.query('UPDATE posts SET likes = likes + 1 WHERE id = ?', [postId]);
            liked = true;
        } else {
            // 取消点赞
            await db.query('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?', [postId, userId]);
            await db.query('UPDATE posts SET likes = GREATEST(likes - 1, 0) WHERE id = ?', [postId]);
            liked = false;
        }

        // 获取最新点赞数
        const [post] = await db.query('SELECT likes FROM posts WHERE id = ?', [postId]);
        newCount = post.length > 0 ? post[0].likes : 0;

        // 返回 JSON（AJAX 请求）或重定向（普通表单）
        if (req.xhr || req.headers.accept?.includes('application/json')) {
            res.json({ success: true, liked, count: newCount });
        } else {
            const [rows] = await db.query('SELECT class_id FROM posts WHERE id = ?', [postId]);
            res.redirect(`/class/${rows[0].class_id}`);
        }
    } catch (err) {
        console.error('点赞失败:', err);
        if (req.xhr || req.headers.accept?.includes('application/json')) {
            res.status(500).json({ success: false, error: '操作失败' });
        } else {
            res.send("操作失败");
        }
    }
});

// 评论（关联用户）
app.post('/post/:id/comment', requireAuth, async (req, res) => {
    try {
        const postId = req.params.id;
        const content = req.body.commentContent;
        const userId = req.session.userId;

        await db.query('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)', [postId, userId, content]);

        const [rows] = await db.query('SELECT class_id FROM posts WHERE id = ?', [postId]);
        res.redirect(`/class/${rows[0].class_id}`);
    } catch (err) {
        console.log(err);
        res.send("操作失败");
    }
});

// 举报（保存到数据库）
app.post('/post/:id/report', requireAuth, async (req, res) => {
    try {
        const postId = req.params.id;
        const reporterId = req.session.userId;

        // 检查是否已举报过
        const [existing] = await db.query(
            'SELECT * FROM reports WHERE post_id = ? AND reporter_id = ? AND status = "pending"',
            [postId, reporterId]
        );

        if (existing.length === 0) {
            await db.query(
                'INSERT INTO reports (post_id, reporter_id) VALUES (?, ?)',
                [postId, reporterId]
            );
        }

        res.send("<script>alert('举报成功，管理员会尽快处理。'); history.back();</script>");
    } catch (err) {
        console.error('举报失败:', err);
        res.send("<script>alert('举报失败，请稍后重试。'); history.back();</script>");
    }
});

// ============================
// 咨询专区（Consultation）路由
// ============================

// 咨询专区首页
app.get('/consultation', requireAuth, async (req, res) => {
    try {
        const [posts] = await db.query(`
            SELECT p.*, u.username 
            FROM consultation_posts p
            LEFT JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
        `);

        // 获取用户对每个帖子的点赞状态
        for (let post of posts) {
            // 分配匿名名字
            if (post.is_anonymous) {
                post.anonymousName = getAnonymousName(post.id, post.user_id, new Set());
            }

            try {
                const [like] = await db.query(
                    'SELECT id FROM consultation_likes WHERE post_id = ? AND user_id = ?',
                    [post.id, req.session.userId]
                );
                post.userLiked = like.length > 0;
            } catch (e) {
                post.userLiked = false;
            }
        }

        res.render('consultation', { posts, moment });
    } catch (err) {
        console.error('加载咨询专区失败:', err);
        res.status(500).send('加载失败');
    }
});

// 新建咨询帖子页面
app.get('/consultation/new', requireAuth, (req, res) => {
    res.render('consultation-new');
});

// 发布咨询帖子
app.post('/consultation/post', requireAuth, upload.array('image', 9), async (req, res) => {
    try {
        const content = req.body.content?.trim();
        const userId = req.session.userId;
        const isAnonymous = req.body.anonymous === 'on' ? 1 : 0;
        
        // 新增字段处理
        const type = req.body.type || 'question';
        const title = req.body.title?.trim() || null;
        const parentId = req.body.parent_id || null;

        if (!content) {
            return res.redirect('/consultation/new');
        }

        let image = '';
        if (req.files && req.files.length > 0) {
            const images = req.files.map(file => '/uploads/' + file.filename);
            image = JSON.stringify(images);
        }

        // 修改插入语句以支持新字段
        await db.query(
            'INSERT INTO consultation_posts (user_id, content, image, is_anonymous, type, title, parent_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [userId, content, image, isAnonymous, type, title, parentId]
        );

        res.redirect('/consultation');
    } catch (err) {
        console.error('发布咨询失败:', err);
        res.send("<script>alert('发布失败，请稍后重试'); history.back();</script>");
    }
});

// 获取提问列表API
app.get('/api/consultation/questions', requireAuth, async (req, res) => {
    try {
        const [posts] = await db.query("SELECT id, title, content FROM consultation_posts WHERE type = 'question' ORDER BY created_at DESC");
        // 处理标题，如果没有标题则截取内容
        const data = posts.map(p => ({
            id: p.id,
            title: p.title || (p.content.length > 30 ? p.content.substring(0, 30) + '...' : p.content)
        }));
        res.json(data);
    } catch (err) {
        console.error(err);
        res.status(500).json([]);
    }
});

// 咨询帖子详情
app.get('/consultation/:id', requireAuth, async (req, res) => {
    try {
        const postId = req.params.id;

        // 获取主帖
        const [posts] = await db.query(`
            SELECT p.*, u.username, u.university, u.school_type, u.graduation_year
            FROM consultation_posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.id = ?
        `, [postId]);

        if (posts.length === 0) {
            return res.redirect('/consultation');
        }
        const post = posts[0];

        // 处理楼主显示身份
        const now = new Date();
        post.displayIdentity = null;
        if (post.school_type === '高中') {
            const gradYear = parseInt(post.graduation_year);
            const gradDate = new Date(gradYear, 5, 9);
            if (now > gradDate) {
                post.displayIdentity = post.university || '大学生';
            }
        }

        // 获取评论
        const [comments] = await db.query(`
            SELECT c.*, u.username, u.university, u.school_type, u.graduation_year
            FROM consultation_comments c
            LEFT JOIN users u ON c.user_id = u.id
            WHERE c.post_id = ?
            ORDER BY c.created_at ASC
        `, [postId]);

        // 构建匿名名字映射
        const anonymousNameMap = buildAnonymousNameMap(post.id, post.user_id, comments);
        
        // 为帖主分配名字
        if (post.is_anonymous) {
            post.anonymousName = anonymousNameMap[post.user_id];
        }

        // 处理评论显示身份
        const now = new Date();
        comments.forEach(comment => {
            // 分配匿名名字
            if (comment.is_anonymous) {
                comment.anonymousName = anonymousNameMap[comment.user_id];
            }

            comment.displayIdentity = null;
            if (comment.school_type === '高中') {
                const gradYear = parseInt(comment.graduation_year);
                const gradDate = new Date(gradYear, 5, 9);
                if (now > gradDate) {
                    comment.displayIdentity = comment.university || '大学生';
                }
            }
        });

        // 检查点赞状态
        const [like] = await db.query(
            'SELECT id FROM consultation_likes WHERE post_id = ? AND user_id = ?',
            [postId, req.session.userId]
        );
        post.userLiked = like.length > 0;

        res.render('consultation-post', { post, comments, moment });
    } catch (err) {
        console.error('加载咨询详情失败:', err);
        res.redirect('/consultation');
    }
});

// 评论咨询帖子
app.post('/consultation/:id/comment', requireAuth, async (req, res) => {
    try {
        const postId = req.params.id;
        const content = req.body.content?.trim();
        const userId = req.session.userId;
        const isAnonymous = req.body.anonymous === 'on' ? 1 : 0;

        if (!content) return res.redirect(`/consultation/${postId}`);

        await db.query(
            'INSERT INTO consultation_comments (post_id, user_id, content, is_anonymous) VALUES (?, ?, ?, ?)',
            [postId, userId, content, isAnonymous]
        );

        await db.query(
            'UPDATE consultation_posts SET reply_count = reply_count + 1 WHERE id = ?',
            [postId]
        );

        res.redirect(`/consultation/${postId}`);
    } catch (err) {
        console.error('评论失败:', err);
        res.redirect(`/consultation/${req.params.id}`);
    }
});

// 点赞咨询帖子 (AJAX/Form)
app.post('/consultation/:id/like', requireAuth, async (req, res) => {
    try {
        const postId = req.params.id;
        const userId = req.session.userId;

        const [existing] = await db.query(
            'SELECT id FROM consultation_likes WHERE post_id = ? AND user_id = ?',
            [postId, userId]
        );

        let liked = false;
        if (existing.length === 0) {
            await db.query('INSERT INTO consultation_likes (post_id, user_id) VALUES (?, ?)', [postId, userId]);
            await db.query('UPDATE consultation_posts SET likes = likes + 1 WHERE id = ?', [postId]);
            liked = true;
        } else {
            await db.query('DELETE FROM consultation_likes WHERE post_id = ? AND user_id = ?', [postId, userId]);
            await db.query('UPDATE consultation_posts SET likes = GREATEST(likes - 1, 0) WHERE id = ?', [postId]);
            liked = false;
        }

        if (req.xhr || req.headers.accept?.includes('application/json')) {
            const [updated] = await db.query('SELECT likes FROM consultation_posts WHERE id = ?', [postId]);
            res.json({ success: true, liked, count: updated[0].likes });
        } else {
            res.redirect(`/consultation/${postId}`);
        }
    } catch (err) {
        console.error('点赞失败:', err);
        if (req.xhr) res.status(500).json({ success: false });
        else res.redirect('back');
    }
});

// 举报咨询帖子
app.post('/consultation/:id/report', requireAuth, async (req, res) => {
    try {
        const postId = req.params.id;
        const reporterId = req.session.userId;
        const reason = req.body.reason || '用户举报';

        // 检查是否已举报过
        const [existing] = await db.query(
            'SELECT id FROM consultation_reports WHERE post_id = ? AND reporter_id = ? AND status = "pending"',
            [postId, reporterId]
        );

        if (existing.length === 0) {
            await db.query(
                'INSERT INTO consultation_reports (post_id, reporter_id, reason) VALUES (?, ?, ?)',
                [postId, reporterId, reason]
            );
        }
        
        res.send('<script>alert("举报已提交，感谢您的反馈！"); window.location.href = "/consultation";</script>');
    } catch (err) {
        console.error('举报失败:', err);
        res.send('<script>alert("举报失败，请稍后重试"); window.history.back();</script>');
    }
});


// ============================
// 树洞（Tree Hole）路由
// ============================

// 树洞首页
app.get('/treehole', requireAuth, async (req, res) => {
    try {
        // 查询主帖（parent_id IS NULL）
        const [posts] = await db.query(`
            SELECT id, content, image, likes, dislikes, reply_count, created_at
            FROM treehole_messages
            WHERE parent_id IS NULL
            ORDER BY created_at DESC
        `);

        // 检查当前用户对每个帖子的交互状态
        for (let post of posts) {
            try {
                const [reaction] = await db.query(
                    'SELECT type FROM treehole_likes WHERE message_id = ? AND user_id = ?',
                    [post.id, req.session.userId]
                );
                post.userAction = reaction.length > 0 ? reaction[0].type : null;
            } catch (err) {
                post.userAction = null;
            }
        }

        res.render('treehole', { posts, moment });
    } catch (err) {
        console.error('加载树洞失败:', err);
        res.status(500).send('加载失败');
    }
});

// 新建帖子页面
app.get('/treehole/new', requireAuth, (req, res) => {
    res.render('treehole-new');
});

// 发布树洞帖子
app.post('/treehole/post', requireAuth, upload.array('image', 9), async (req, res) => {
    try {
        const content = req.body.content?.trim();
        const userId = req.session.userId;

        if (!content) {
            return res.redirect('/treehole/new');
        }

        let image = '';
        if (req.files && req.files.length > 0) {
            const images = req.files.map(file => '/uploads/' + file.filename);
            image = JSON.stringify(images);
        }

        // 发主帖 - parent_id 为 NULL
        const [result] = await db.query(
            'INSERT INTO treehole_messages (user_id, parent_id, content, image) VALUES (?, NULL, ?, ?)',
            [userId, content, image]
        );

        // 跳转到新创建的帖子详情页
        res.redirect(`/treehole/${result.insertId}`);
    } catch (err) {
        console.error('发布帖子失败:', err);
        res.send("<script>alert('发布失败，请稍后重试'); history.back();</script>");
    }
});

// 查看树洞帖子详情
app.get('/treehole/:id', requireAuth, async (req, res) => {
    try {
        const postId = req.params.id;

        // 处理 /treehole/new 路由冲突
        if (postId === 'new') {
            return res.render('treehole-new');
        }

        // 获取主帖 (增加 dislikes 字段)
        const [posts] = await db.query(
            'SELECT id, user_id, content, image, likes, dislikes, reply_count, created_at FROM treehole_messages WHERE id = ? AND parent_id IS NULL',
            [postId]
        );

        if (posts.length === 0) {
            return res.redirect('/treehole');
        }

        const post = posts[0];

        // 检查主帖交互状态
        try {
            const [reaction] = await db.query(
                'SELECT type FROM treehole_likes WHERE message_id = ? AND user_id = ?',
                [postId, req.session.userId]
            );
            post.userAction = reaction.length > 0 ? reaction[0].type : null;
        } catch (err) {
            post.userAction = null;
        }

        // 获取回复列表（parent_id = 主帖ID）
        const [replies] = await db.query(`
            SELECT id, user_id, parent_id, content, image, created_at, likes, dislikes
            FROM treehole_messages
            WHERE parent_id = ?
            ORDER BY id ASC
        `, [postId]);

        // 构建匿名名字映射
        const anonymousNameMap = buildAnonymousNameMap(post.id, post.user_id, replies);

        // 为帖主分配名字
        post.anonymousName = anonymousNameMap[post.user_id];

        // 批量查询所有回复的点赞状态以减少数据库查询次数（略过复杂，这里用循环简单实现）
        // 为每条回复分配匿名名字并解析引用（使用全局ID）
        for (const reply of replies) {
            reply.anonymousName = anonymousNameMap[reply.user_id];
            reply.isOP = reply.user_id === post.user_id; // 是否为洞主
            reply.quotes = await parseQuotes(reply.content, postId);

            // 查询回复的交互状态
            try {
                const [rReaction] = await db.query(
                    'SELECT type FROM treehole_likes WHERE message_id = ? AND user_id = ?',
                    [reply.id, req.session.userId]
                );
                reply.userAction = rReaction.length > 0 ? rReaction[0].type : null;
            } catch {
                reply.userAction = null;
            }
        }

        res.render('treehole-post', { post, replies, moment, postUserId: post.user_id });
    } catch (err) {
        console.error('加载帖子详情失败:', err);
        res.status(500).send('加载失败');
    }
});

// 回复树洞帖子
app.post('/treehole/:id/reply', requireAuth, upload.single('image'), async (req, res) => {
    try {
        const postId = req.params.id;
        const content = req.body.content?.trim();
        const userId = req.session.userId;

        if (!content) {
            return res.redirect(`/treehole/${postId}`);
        }

        let image = '';
        if (req.file) {
            image = '/uploads/' + req.file.filename;
        }

        // 插入回复 - parent_id 为主帖ID，使用自增ID作为全局唯一标识
        await db.query(
            'INSERT INTO treehole_messages (user_id, parent_id, content, image) VALUES (?, ?, ?, ?)',
            [userId, postId, content, image]
        );

        // 更新主帖回复数
        await db.query(
            'UPDATE treehole_messages SET reply_count = reply_count + 1 WHERE id = ?',
            [postId]
        );

        res.redirect(`/treehole/${postId}`);
    } catch (err) {
        console.error('回复失败:', err);
        res.send("<script>alert('回复失败，请稍后重试'); history.back();</script>");
    }
});

// 点赞树洞帖子（AJAX）
// 树洞交互：点赞/点踩 (AJAX)
app.post('/treehole/:id/react', requireAuth, async (req, res) => {
    try {
        const messageId = req.params.id;
        const userId = req.session.userId;
        const type = req.body.type; // 'like' 或 'dislike'

        if (!['like', 'dislike'].includes(type)) {
            return res.status(400).json({ success: false, error: '无效的操作类型' });
        }

        // 检查用户当前的交互状态
        const [existing] = await db.query(
            'SELECT id, type FROM treehole_likes WHERE message_id = ? AND user_id = ?',
            [messageId, userId]
        );

        let currentUserAction = null; // null, 'like', 'dislike'

        if (existing.length > 0) {
            const currentType = existing[0].type;

            if (currentType === type) {
                // 如果是重复操作（如已赞点赞），则取消
                await db.query('DELETE FROM treehole_likes WHERE id = ?', [existing[0].id]);
                if (type === 'like') {
                    await db.query('UPDATE treehole_messages SET likes = GREATEST(likes - 1, 0) WHERE id = ?', [messageId]);
                } else {
                    await db.query('UPDATE treehole_messages SET dislikes = GREATEST(dislikes - 1, 0) WHERE id = ?', [messageId]);
                }
                currentUserAction = null;
            } else {
                // 如果是反向操作（如已赞点踩），则更新类型并更新计数
                await db.query('UPDATE treehole_likes SET type = ? WHERE id = ?', [type, existing[0].id]);
                // 更新计数：旧类型-1，新类型+1
                if (type === 'like') { // 从踩变赞
                    await db.query('UPDATE treehole_messages SET dislikes = GREATEST(dislikes - 1, 0), likes = likes + 1 WHERE id = ?', [messageId]);
                } else { // 从赞变踩
                    await db.query('UPDATE treehole_messages SET likes = GREATEST(likes - 1, 0), dislikes = dislikes + 1 WHERE id = ?', [messageId]);
                }
                currentUserAction = type;
            }
        } else {
            // 新操作
            await db.query('INSERT INTO treehole_likes (message_id, user_id, type) VALUES (?, ?, ?)', [messageId, userId, type]);
            if (type === 'like') {
                await db.query('UPDATE treehole_messages SET likes = likes + 1 WHERE id = ?', [messageId]);
            } else {
                await db.query('UPDATE treehole_messages SET dislikes = dislikes + 1 WHERE id = ?', [messageId]);
            }
            currentUserAction = type;
        }

        // 获取最新计数
        const [msg] = await db.query('SELECT likes, dislikes FROM treehole_messages WHERE id = ?', [messageId]);

        res.json({
            success: true,
            likes: msg[0].likes,
            dislikes: msg[0].dislikes,
            userAction: currentUserAction
        });

    } catch (err) {
        console.error('交互失败:', err);
        res.status(500).json({ success: false, error: '操作失败' });
    }
});

// 举报树洞帖子
app.post('/treehole/:id/report', requireAuth, async (req, res) => {
    try {
        const messageId = req.params.id;
        const reporterId = req.session.userId;
        const reason = req.body.reason || '用户举报';

        // 检查是否已举报
        const [existing] = await db.query(
            'SELECT id FROM treehole_reports WHERE message_id = ? AND reporter_id = ? AND status = "pending"',
            [messageId, reporterId]
        );

        if (existing.length === 0) {
            await db.query(
                'INSERT INTO treehole_reports (message_id, reporter_id, reason) VALUES (?, ?, ?)',
                [messageId, reporterId, reason]
            );
        }

        res.json({ success: true });
    } catch (err) {
        console.error('举报失败:', err);
        res.status(500).json({ success: false, error: '举报提交失败' });
    }
});


app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});