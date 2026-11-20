"""Pytest 共享夹具：为每条用例提供隔离的 SQLite 库、fakeredis 缓存与 TestClient。"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Dict, Generator

import pytest
from fastapi.testclient import TestClient

from app.cache import reset_cache_for_test
from app.config import get_settings
from app.db import init_db, reset_engine_for_test
from app.main import create_app
from app.services.signature import compute_signature

BROWSER_HEADERS: Dict[str, str] = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Sec-CH-UA": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}


def make_signed_headers(
    method: str,
    path: str,
    *,
    ts: int | None = None,
    nonce: str | None = None,
    secret: str | None = None,
) -> Dict[str, str]:
    settings = get_settings()
    ts_str = str(ts if ts is not None else int(time.time()))
    nonce_str = nonce or uuid.uuid4().hex
    sig = compute_signature(secret or settings.sign_secret, method, path, ts_str, nonce_str)
    return {
        "X-Signature": sig,
        "X-Timestamp": ts_str,
        "X-Nonce": nonce_str,
    }


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    db_file = tmp_path / "test_anticrawl.db"
    db_url = f"sqlite:///{db_file.as_posix()}"

    monkeypatch.setenv("LAB_MODE", "1")
    monkeypatch.setenv("ENABLE_LIVE_GEOIP", "0")
    monkeypatch.setenv("REDIS_URL", "")
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SIGN_SECRET", "change-me-in-lab")
    monkeypatch.setenv("RATE_LIMIT_QPS", "10")
    monkeypatch.setenv("FP_RATE_LIMIT_QPS", "30")
    monkeypatch.setenv("POW_DIFFICULTY", "2")

    reset_cache_for_test("")
    reset_engine_for_test(db_url)
    init_db(db_url)

    app = create_app()
    with TestClient(app) as tc:
        yield tc

    reset_cache_for_test("")
    # 确保测试退出前释放连接
    os.environ.pop("DATABASE_URL", None)
