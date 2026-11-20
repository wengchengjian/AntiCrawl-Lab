"""
AntiCrawl Lab 全局配置模块。
从环境变量或项目根目录 .env 加载服务与风控参数。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_DIR.parent

# 仅当 .env 存在时加载（不覆盖已显式注入的进程环境变量）
_ENV_FILE = PROJECT_ROOT / ".env"
if _ENV_FILE.exists():
    load_dotenv(_ENV_FILE, override=False)


@dataclass(frozen=True)
class Settings:
    """不可变配置快照，支持单测通过环境变量动态覆盖。"""

    frontend_port: int
    backend_port: int
    lab_mode: bool
    database_url: str
    redis_url: str
    rate_limit_qps: int
    fp_rate_limit_qps: int
    ban_seconds: int
    sign_secret: str
    sign_window_seconds: int
    nonce_ttl_seconds: int
    pow_difficulty: int
    data_retention_days: int
    anon_max_page: int
    anon_max_views: int
    public_bucket_burst: int
    public_bucket_rate: int
    sensitive_bucket_burst: int
    sensitive_bucket_rate: int
    allowed_origins: list[str]


def _clean_env(val: str | None) -> str:
    """清理 systemd EnvironmentFile 可能带入的行内 `#` 注释与首尾空白。"""
    if val is None:
        return ""
    return val.split("#", 1)[0].strip()


def _parse_bool(val: str | None, default: bool) -> bool:
    cleaned = _clean_env(val)
    if not cleaned:
        return default
    return cleaned.lower() in {"1", "true", "yes", "on"}


def _parse_int(key: str, default: int) -> int:
    cleaned = _clean_env(os.getenv(key))
    if not cleaned:
        return default
    return int(cleaned)


def get_settings() -> Settings:
    """读取当前环境变量构建配置对象。"""
    frontend_port = _parse_int("FRONTEND_PORT", 5173)
    backend_port = _parse_int("BACKEND_PORT", 8000)
    lab_mode = _parse_bool(os.getenv("LAB_MODE"), default=True)
    default_db = f"sqlite:///{(BACKEND_DIR / 'anticrawl.db').as_posix()}"
    database_url = _clean_env(os.getenv("DATABASE_URL")) or default_db
    redis_url = _clean_env(os.getenv("REDIS_URL"))

    if lab_mode:
        allowed_origins = [
            f"http://127.0.0.1:{frontend_port}",
            f"http://localhost:{frontend_port}",
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "*",
        ]
    else:
        allowed_origins = [
            f"http://127.0.0.1:{frontend_port}",
            f"http://localhost:{frontend_port}",
        ]

    return Settings(
        frontend_port=frontend_port,
        backend_port=backend_port,
        lab_mode=lab_mode,
        database_url=database_url,
        redis_url=redis_url,
        rate_limit_qps=_parse_int("RATE_LIMIT_QPS", 10),
        fp_rate_limit_qps=_parse_int("FP_RATE_LIMIT_QPS", 30),
        ban_seconds=_parse_int("BAN_SECONDS", 600),
        sign_secret=_clean_env(os.getenv("SIGN_SECRET")) or "change-me-in-lab",
        sign_window_seconds=_parse_int("SIGN_WINDOW_SECONDS", 120),
        nonce_ttl_seconds=_parse_int("NONCE_TTL_SECONDS", 300),
        pow_difficulty=_parse_int("POW_DIFFICULTY", 4),
        data_retention_days=_parse_int("DATA_RETENTION_DAYS", 7),
        anon_max_page=_parse_int("ANON_MAX_PAGE", 2),
        anon_max_views=_parse_int("ANON_MAX_VIEWS", 15),
        public_bucket_burst=_parse_int("PUBLIC_BUCKET_BURST", 60),
        public_bucket_rate=_parse_int("PUBLIC_BUCKET_RATE", 30),
        sensitive_bucket_burst=_parse_int("SENSITIVE_BUCKET_BURST", 8),
        sensitive_bucket_rate=_parse_int("SENSITIVE_BUCKET_RATE", 4),
        allowed_origins=allowed_origins,
    )
