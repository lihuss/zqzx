#!/usr/bin/env bash
set -e

# 示例 restart.sh：根据你的应用修改以下命令

echo "Running restart.sh on $(hostname)"

# 如果是 Node.js + pm2：
if command -v pm2 >/dev/null 2>&1; then
  echo "Restarting app with pm2..."
  pm2 restart all || pm2 start ecosystem.config.js --env production || true
fi

# 如果使用 docker-compose：
if [ -f docker-compose.yml ]; then
  echo "Using docker-compose to restart..."
  docker-compose pull || true
  docker-compose up -d --remove-orphans
fi

echo "Restart script finished."
