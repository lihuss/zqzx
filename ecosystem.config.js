module.exports = {
    apps: [{
        name: 'zqzx-memory',
        script: 'server.js',
        instances: 1,
        autorestart: true,
        watch: false,
        max_memory_restart: '500M',
        env: {
            NODE_ENV: 'development',
            PORT: 3000
        },
        env_production: {
            NODE_ENV: 'production',
            PORT: 3000,
            // 如果需要自定义上传目录，取消下面这行的注释
            // UPLOADS_DIR: '/var/www/zqzx-uploads'
        }
    }]
};
