"""
ws.py — WebSocket endpoint for live alert push to the dashboard.
"""
import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import redis.asyncio as aioredis
import os

router = APIRouter(tags=["websocket"])
logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
ALERT_CHANNEL = "rsentry:alerts"


class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)
        logger.info("WS client connected. Total: %d", len(self._connections))

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)
        logger.info("WS client disconnected. Total: %d", len(self._connections))

    async def broadcast(self, message: dict):
        data = json.dumps(message)
        dead: list[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Subscribe to Redis pub/sub for live alerts
        redis = aioredis.from_url(REDIS_URL, decode_responses=True)
        pubsub = redis.pubsub()
        await pubsub.subscribe(ALERT_CHANNEL)

        async def redis_reader():
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        payload = json.loads(message["data"])
                        await manager.broadcast(payload)
                    except json.JSONDecodeError:
                        pass

        # Run redis reader concurrently with websocket keepalive
        reader_task = asyncio.create_task(redis_reader())
        try:
            while True:
                # Keep the connection alive; client can send pings
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text("pong")
        finally:
            reader_task.cancel()
            await pubsub.unsubscribe(ALERT_CHANNEL)
            await redis.aclose()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as exc:
        logger.error("WS error: %s", exc)
        manager.disconnect(websocket)


async def publish_alert(alert_data: dict[str, Any]) -> None:
    """Called by Celery task (via asyncio bridge) to push alert to Redis channel."""
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis.publish(ALERT_CHANNEL, json.dumps(alert_data))
    finally:
        await redis.aclose()
