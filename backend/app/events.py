"""
SSE 实时事件广播总线（events.py）。
支持多仪表盘客户端订阅 `event: risk` 事件，异步无阻塞广播。
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncGenerator, Dict, Set


class EventBus:
    """内存广播总线，向所有在线仪表盘推送风控日志事件。"""

    def __init__(self) -> None:
        self._subscribers: Set[asyncio.Queue[Dict[str, Any]]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def subscribe(self) -> asyncio.Queue[Dict[str, Any]]:
        """注册一个新的 SSE 监听队列。"""
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=256)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Dict[str, Any]]) -> None:
        """注销 SSE 监听队列。"""
        self._subscribers.discard(queue)

    def publish(self, event_payload: Dict[str, Any]) -> None:
        """广播风控事件到所有订阅者；队列满时丢弃最旧消息避免阻塞业务请求。"""
        for queue in list(self._subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(event_payload)
            except asyncio.QueueFull:
                pass

    @staticmethod
    def format_sse(event_name: str, payload: Dict[str, Any]) -> str:
        """按标准 SSE 帧格式输出：`event: risk\\ndata: {...}\\n\\n`。"""
        data_str = json.dumps(payload, ensure_ascii=False)
        return f"event: {event_name}\ndata: {data_str}\n\n"

    async def stream(self, heartbeat_seconds: float = 15.0) -> AsyncGenerator[str, None]:
        """生成实时 SSE 字节流；无新事件时定期发送注释心跳保活。"""
        queue = self.subscribe()
        try:
            # 立即发送连接确认注释帧，防止代理层/浏览器等待首字节超时
            yield ": connected\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=heartbeat_seconds)
                    yield self.format_sse("risk", payload)
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            self.unsubscribe(queue)


_event_bus = EventBus()


def get_event_bus() -> EventBus:
    """获取全局唯一 SSE 事件广播总线。"""
    return _event_bus
