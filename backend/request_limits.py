import json
from typing import Callable, Awaitable

from starlette.types import ASGIApp, Scope, Receive, Send, Message


class RequestSizeLimitMiddleware:
    """
    Limits HTTP request body size before it reaches FastAPI endpoints.

    This is safer than only checking the Content-Length header because some
    clients may omit or manipulate that header.

    For this project, the middleware reads the body up to a safe limit,
    rejects oversized requests, then replays the body to FastAPI.
    """

    def __init__(self, app: ASGIApp, max_body_size: int = 1_000_000):
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }

        content_length = headers.get("content-length")

        if content_length is not None:
            try:
                if int(content_length) > self.max_body_size:
                    await self._send_too_large_response(send)
                    return
            except ValueError:
                await self._send_bad_request_response(send)
                return

        body = b""
        more_body = True

        while more_body:
            message = await receive()

            if message["type"] != "http.request":
                continue

            chunk = message.get("body", b"")
            body += chunk

            if len(body) > self.max_body_size:
                await self._send_too_large_response(send)
                return

            more_body = message.get("more_body", False)

        async def replay_receive() -> Message:
            return {
                "type": "http.request",
                "body": body,
                "more_body": False
            }

        await self.app(scope, replay_receive, send)

    async def _send_too_large_response(self, send: Send) -> None:
        await self._send_json_response(
            send=send,
            status_code=413,
            payload={
                "detail": "Request body too large",
                "max_body_size_bytes": self.max_body_size
            }
        )

    async def _send_bad_request_response(self, send: Send) -> None:
        await self._send_json_response(
            send=send,
            status_code=400,
            payload={
                "detail": "Invalid Content-Length header"
            }
        )

    async def _send_json_response(
        self,
        send: Send,
        status_code: int,
        payload: dict
    ) -> None:
        response_body = json.dumps(payload).encode("utf-8")

        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(response_body)).encode("latin-1")]
            ]
        })

        await send({
            "type": "http.response.body",
            "body": response_body
        })