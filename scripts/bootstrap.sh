#!/usr/bin/env bash
set -euo pipefail

# AntiCrawl Lab 一键启动脚本（Linux / macOS / Git Bash）
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
  echo "[bootstrap] Copied .env.example -> .env"
fi

# 加载环境变量
if [ -f ".env" ]; then
  set -a
  # shellcheck disable=SC1091
  source <(sed 's/#.*$//' .env | grep -E '^[A-Za-z_][A-Za-z0-9_]*=')
  set +a
fi

BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"

# 1. Python 虚拟环境与依赖
if [ ! -d "backend/.venv" ]; then
  echo "[bootstrap] Creating Python venv..."
  python3 -m venv backend/.venv || python -m venv backend/.venv
fi

if [ -x "backend/.venv/bin/python" ]; then
  PY_BIN="backend/.venv/bin/python"
  PIP_BIN="backend/.venv/bin/pip"
else
  PY_BIN="backend/.venv/Scripts/python.exe"
  PIP_BIN="backend/.venv/Scripts/pip.exe"
fi

"$PIP_BIN" install -q -r backend/requirements.txt

# 2. 构建期生成动态字体
echo "[bootstrap] Generating dynamic anti-crawl fonts..."
"$PY_BIN" scripts/make_font.py

# 3. 初始化 SQLite 五表与预置数据
echo "[bootstrap] Initializing SQLite schema & seed data..."
(cd backend && "../$PY_BIN" -c "from app.db import init_db; init_db()")

# 4. 安装前端依赖（如尚未安装）
if [ ! -d "frontend/node_modules" ]; then
  echo "[bootstrap] Installing frontend dependencies..."
  (cd frontend && npm install)
fi

cleanup() {
  echo ""
  echo "[bootstrap] Stopping AntiCrawl Lab services..."
  kill "${BACK_PID:-}" "${FRONT_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# 5. 并发启动后端（默认仅监听 127.0.0.1）与前端
echo "[bootstrap] Starting backend on http://127.0.0.1:${BACKEND_PORT} ..."
(cd backend && "../$PY_BIN" -m uvicorn app.main:app --host 127.0.0.1 --port "${BACKEND_PORT}") &
BACK_PID=$!

echo "[bootstrap] Starting frontend on http://127.0.0.1:${FRONTEND_PORT} ..."
(cd frontend && npm run dev -- --host 127.0.0.1 --port "${FRONTEND_PORT}") &
FRONT_PID=$!

echo "[bootstrap] Ready! Frontend: http://127.0.0.1:${FRONTEND_PORT} | Backend: http://127.0.0.1:${BACKEND_PORT}"
wait
