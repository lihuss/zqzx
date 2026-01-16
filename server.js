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
            res.locals.user = user;
        } catch (err) {
            console.error('获取用户信息失败:', err);
        }
    }
    next();
});

// 登录验证中间件
function requireAuth(req, res, next) {
    if (!req.session.userId) {
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

// --- 认证路由 ---

// 登录页
app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/hall');
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
        res.redirect('/hall');
    } catch (err) {
        console.error('登录失败:', err);
        res.render('login', { error: '登录失败，请稍后重试', success: null });
    }
});

// 注册页
app.get('/register', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/hall');
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

// 我的邀请码
app.get('/my-codes', requireAuth, async (req, res) => {
    try {
        const codes = await auth.getUserInviteCodes(req.session.userId);
        res.render('my-codes', { codes });
    } catch (err) {
        console.error('获取邀请码失败:', err);
        res.redirect('/hall');
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
    try {
        const [rows] = await db.query(`
            SELECT r.*, p.content as post_content, p.class_id, u.username as reporter_name
            FROM reports r
            LEFT JOIN posts p ON r.post_id = p.id
            LEFT JOIN users u ON r.reporter_id = u.id
            ORDER BY r.created_at DESC
        `);
        reports = rows;
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
app.post('/class/:id/post', requireAuth, upload.single('image'), async (req, res) => {
    try {
        const classId = req.params.id;
        const content = req.body.content;
        const userId = req.session.userId;
        const isAnonymous = req.body.anonymous === 'on' ? 1 : 0;
        let image = '';
        if (req.file) {
            image = '/uploads/' + req.file.filename;
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

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});