"""
SQLite 数据库连接、WAL 模式配置、Session 工厂与预置数据种子。
"""

from __future__ import annotations

from typing import Dict, Generator, List

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.models.tables import Base, IpGeoMock

# 预置 14 条本地演练 GeoIP 样例（满足提示词第 5 章与 8.3 节要求：含上海/北京住宅、美国/香港机房、黑名单段）
SEED_IP_GEO: List[Dict[str, object]] = [
    {
        "ip_prefix": "116.228.",
        "country": "CN",
        "city": "Shanghai",
        "asn": "AS4812 ChinaNet Shanghai Residential",
        "is_datacenter": 0,
        "is_blacklist": 0,
    },
    {
        "ip_prefix": "180.168.",
        "country": "CN",
        "city": "Shanghai",
        "asn": "AS4812 ChinaNet Shanghai Broadband",
        "is_datacenter": 0,
        "is_blacklist": 0,
    },
    {
        "ip_prefix": "123.125.",
        "country": "CN",
        "city": "Beijing",
        "asn": "AS4808 China Unicom Beijing Residential",
        "is_datacenter": 0,
        "is_blacklist": 0,
    },
    {
        "ip_prefix": "114.242.",
        "country": "CN",
        "city": "Beijing",
        "asn": "AS4808 China Unicom Beijing Fiber",
        "is_datacenter": 0,
        "is_blacklist": 0,
    },
    {
        "ip_prefix": "113.108.",
        "country": "CN",
        "city": "Guangzhou",
        "asn": "AS4134 ChinaNet Guangdong Residential",
        "is_datacenter": 0,
        "is_blacklist": 0,
    },
    {
        "ip_prefix": "52.95.",
        "country": "US",
        "city": "Ashburn",
        "asn": "AS16509 Amazon AWS Datacenter",
        "is_datacenter": 1,
        "is_blacklist": 0,
    },
    {
        "ip_prefix": "34.102.",
        "country": "US",
        "city": "Mountain View",
        "asn": "AS15169 Google Cloud Datacenter",
        "is_datacenter": 1,
        "is_blacklist": 0,
    },
    {
        "ip_prefix": "54.239.",
        "country": "US",
        "city": "Boardman",
        "asn": "AS16509 Amazon EC2 US-West",
        "is_datacenter": 1,
        "is_blacklist": 0,
    },
    {
        "ip_prefix": "47.242.",
        "country": "HK",
        "city": "Hong Kong",
        "asn": "AS45102 Alibaba Cloud HK Datacenter",
        "is_datacenter": 1,
        "is_blacklist": 0,
    },
    {
        "ip_prefix": "13.228.",
        "country": "SG",
        "city": "Singapore",
        "asn": "AS16509 Amazon AWS Singapore",
        "is_datacenter": 1,
        "is_blacklist": 0,
    },
    {
        "ip_prefix": "198.51.100.",
        "country": "US",
        "city": "Test-Net-2 Blacklist",
        "asn": "AS64512 Abuse Blacklist Pool",
        "is_datacenter": 1,
        "is_blacklist": 1,
    },
    {
        "ip_prefix": "203.0.113.",
        "country": "SG",
        "city": "Test-Net-3 Blacklist",
        "asn": "AS64513 Scraper Botnet Pool",
        "is_datacenter": 1,
        "is_blacklist": 1,
    },
    {
        "ip_prefix": "192.0.2.",
        "country": "DE",
        "city": "Test-Net-1 Blacklist",
        "asn": "AS64514 Known Proxy Exit",
        "is_datacenter": 1,
        "is_blacklist": 1,
    },
    {
        "ip_prefix": "127.0.0.",
        "country": "CN",
        "city": "Localhost Lab",
        "asn": "AS0 Local Loopback",
        "is_datacenter": 0,
        "is_blacklist": 0,
    },
]

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None
_current_db_url: str | None = None


def _configure_sqlite(dbapi_connection: object, _connection_record: object) -> None:
    """为 SQLite 开启 WAL 日志与 NORMAL 同步，提升并发读写性能。"""
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()


def get_engine(database_url: str | None = None) -> Engine:
    """获取或初始化全局 SQLAlchemy Engine。"""
    global _engine, _SessionLocal, _current_db_url
    url = database_url or get_settings().database_url
    if _engine is not None and _current_db_url == url:
        return _engine

    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, connect_args=connect_args, future=True)
    if url.startswith("sqlite"):
        event.listen(engine, "connect", _configure_sqlite)

    _engine = engine
    _current_db_url = url
    _SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    return _engine


def get_session_factory(database_url: str | None = None) -> sessionmaker[Session]:
    """获取当前 sessionmaker 工厂。"""
    get_engine(database_url)
    assert _SessionLocal is not None
    return _SessionLocal


def reset_engine_for_test(database_url: str) -> Engine:
    """仅用于测试：切换数据库路径并重置连接池。"""
    global _engine, _SessionLocal, _current_db_url
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
    _current_db_url = None
    return get_engine(database_url)


def init_db(database_url: str | None = None) -> None:
    """建表并幂等插入 ip_geo_mock 预置样例。"""
    engine = get_engine(database_url)
    Base.metadata.create_all(bind=engine)
    factory = get_session_factory(database_url)
    with factory() as session:
        for row in SEED_IP_GEO:
            existing = session.get(IpGeoMock, row["ip_prefix"])
            if existing is None:
                session.add(IpGeoMock(**row))
        session.commit()


def get_db() -> Generator[Session, None, None]:
    """FastAPI 依赖注入：提供请求级数据库 Session。"""
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()
