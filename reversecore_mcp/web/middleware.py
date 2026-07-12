"""
ASGI Middleware for security headers.
"""


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))

                # Helper to check if header is already present
                def has_header(name_bytes):
                    return any(h[0].lower() == name_bytes for h in headers)

                if not has_header(b"strict-transport-security"):
                    headers.append(
                        (
                            b"strict-transport-security",
                            b"max-age=31536000; includeSubDomains",
                        )
                    )
                if not has_header(b"x-content-type-options"):
                    headers.append((b"x-content-type-options", b"nosniff"))
                if not has_header(b"x-frame-options"):
                    headers.append((b"x-frame-options", b"DENY"))
                if not has_header(b"content-security-policy"):
                    headers.append((b"content-security-policy", b"default-src 'self'"))

                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)
