"""Utilities for streaming SSH terminals over WebSockets."""
from __future__ import annotations

import inspect
import json
from contextlib import suppress
from typing import Any, Awaitable, Callable

import anyio
from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect, WebSocketState


CloseCallback = Callable[[], Awaitable[None] | None] | None


async def send_websocket_json(websocket: WebSocket, payload: dict[str, Any]) -> None:
    """Safely send a JSON payload to a websocket client."""

    if websocket.client_state == WebSocketState.DISCONNECTED:
        return
    with suppress(Exception):
        await websocket.send_json(payload)


async def stream_ssh_channel(
    websocket: WebSocket,
    channel: Any,
    *,
    on_close: CloseCallback = None,
) -> None:
    """Bridge data between a websocket and an interactive SSH channel."""

    cancel_exc = anyio.get_cancelled_exc_class()
    closed = False

    async def cleanup() -> None:
        nonlocal closed
        if closed:
            return
        closed = True
        if on_close is not None:
            try:
                result = on_close()
                if inspect.isawaitable(result):
                    await result
            except Exception:
                pass
        with suppress(Exception):
            await anyio.to_thread.run_sync(channel.close, abandon_on_cancel=True)
        with suppress(Exception):
            if websocket.application_state != WebSocketState.DISCONNECTED:
                await websocket.close()

    async def pump_ssh_to_websocket(task_group) -> None:
        try:
            while True:
                data = await anyio.to_thread.run_sync(
                    channel.recv,
                    4096,
                    abandon_on_cancel=True,
                )
                if not data:
                    break
                try:
                    await websocket.send_bytes(data)
                except Exception:
                    break
        except cancel_exc:
            pass
        except Exception:
            pass
        finally:
            task_group.cancel_scope.cancel()
            await cleanup()

    async def pump_websocket_to_ssh(task_group) -> None:
        try:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    break
                data = message.get("bytes")
                if data is not None:
                    if data:
                        with suppress(Exception):
                            await anyio.to_thread.run_sync(channel.send, data)
                    continue
                text = message.get("text")
                if text is None:
                    continue
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    encoded = text.encode("utf-8", errors="ignore")
                    if encoded:
                        with suppress(Exception):
                            await anyio.to_thread.run_sync(channel.send, encoded)
                    continue
                message_type = payload.get("type")
                if message_type == "resize":
                    cols = payload.get("cols")
                    rows = payload.get("rows")
                    try:
                        width = int(cols) if cols else 0
                    except (TypeError, ValueError):
                        width = 0
                    try:
                        height = int(rows) if rows else 0
                    except (TypeError, ValueError):
                        height = 0
                    width = width if width > 0 else 80
                    height = height if height > 0 else 24
                    with suppress(Exception):
                        await anyio.to_thread.run_sync(channel.resize_pty, width, height)
                    continue
                if message_type == "close":
                    break
        except (WebSocketDisconnect, cancel_exc):
            pass
        except Exception:
            pass
        finally:
            task_group.cancel_scope.cancel()
            await cleanup()

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(pump_ssh_to_websocket, task_group)
        task_group.start_soon(pump_websocket_to_ssh, task_group)

    await cleanup()


__all__ = ["send_websocket_json", "stream_ssh_channel"]

