"""
SQLAlchemy 2.x 数据表模型定义。
严格限定为第 5 章规定的 5 张表：risk_logs, fingerprints, bans, ip_geo_mock, nonces。
"""

from __future__ import annotations

from sqlalchemy import Integer, Float, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """ORM 模型基类。"""


class RiskLog(Base):
    """风控审计日志表（risk_logs）。"""

    __tablename__ = "risk_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    client_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    effective_ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    path: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    module: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reasons: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    ua: Mapped[str] = mapped_column(Text, nullable=False, default="")
    fingerprint_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False, default="")
    decoy_served: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # 扩展字段：记录 8 步流水线详情、环境伪装破绽分组与增强探针信号
    extra_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class Fingerprint(Base):
    """浏览器指纹画像表（fingerprints）。"""

    __tablename__ = "fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    fp_id: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    ua: Mapped[str] = mapped_column(Text, nullable=False, default="")
    platform: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    languages: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    screen_width: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    screen_height: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    color_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    device_pixel_ratio: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    device_memory: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    hardware_concurrency: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    touch_points: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    canvas_hash: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    webgl_vendor: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    webgl_renderer: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    webgl_masked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    audio_hash: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    font_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fonts_hash: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    automation_flags: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    last_seen_at: Mapped[str] = mapped_column(String(40), nullable=False)
    hit_ips: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # 扩展字段：保存增强探针原始摘要（Canvas 噪点/Math/Worker/WebRTC/Iframe）
    extra_probes: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class Ban(Base):
    """IP 封禁记录表（bans）。"""

    __tablename__ = "bans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    banned_at: Mapped[str] = mapped_column(String(40), nullable=False)
    ban_until: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    lifted_at: Mapped[str | None] = mapped_column(String(40), nullable=True, default=None)
    lifted_by: Mapped[str | None] = mapped_column(String(32), nullable=True, default=None)


class IpGeoMock(Base):
    """本地 Mock GeoIP 与信誉库表（ip_geo_mock）。"""

    __tablename__ = "ip_geo_mock"

    ip_prefix: Mapped[str] = mapped_column(String(64), primary_key=True)
    country: Mapped[str] = mapped_column(String(16), nullable=False)
    city: Mapped[str] = mapped_column(String(64), nullable=False)
    asn: Mapped[str] = mapped_column(String(64), nullable=False)
    is_datacenter: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_blacklist: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class Nonce(Base):
    """签名 Nonce 去重审计镜像表（nonces）。"""

    __tablename__ = "nonces"

    nonce: Mapped[str] = mapped_column(String(128), primary_key=True)
    ts: Mapped[int] = mapped_column(Integer, nullable=False)
    expired_at: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
