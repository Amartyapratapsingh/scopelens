"""Synthetic exposure lab. `create_app(False)` is the independently different fixed variant."""

import json

from fastapi import FastAPI, Response


def create_app(vulnerable: bool = True, *, fallback: bool = False) -> FastAPI:
    app = FastAPI()
    secret = "synthetic-only-not-a-credential"
    routes = {
        "/.env": (f"APP_NAME=ScopeLensLab\nDB_PASSWORD={secret}\n", "text/plain"),
        "/config.json.bak": (json.dumps({"db": {"password": secret}}), "application/json"),
        "/wp-config.php.bak": (
            "<?php define('DB_USER', 'synthetic'); define('DB_PASSWORD', 'synthetic');",
            "text/plain",
        ),
        "/phpinfo.php": (
            "<html><title>phpinfo()</title>PHP Version 8.2 DOCUMENT_ROOT SERVER_SOFTWARE</html>",
            "text/html",
        ),
        "/server-status": (
            "Total Accesses: 4\nTotal kBytes: 40\nBusyWorkers: 2\nIdleWorkers: 4\n",
            "text/plain",
        ),
        "/actuator/env": (
            json.dumps(
                {"propertySources": [{"properties": {"database.password": {"value": secret}}}]}
            ),
            "application/json",
        ),
        "/actuator/configprops": (
            json.dumps({"contexts": {"app": {"beans": {"datasource": {"password": secret}}}}}),
            "application/json",
        ),
        "/app.js.map": (
            json.dumps(
                {
                    "version": 3,
                    "sources": ["private.js"],
                    "sourcesContent": [f'const client_secret = "{secret}";'],
                }
            ),
            "application/json",
        ),
    }

    @app.get("/{path:path}")
    def serve(path: str):
        if fallback:
            return Response(routes["/.env"][0], media_type="text/plain")
        if "/" + path == "/server.key":
            return Response("not a key", media_type="text/plain", status_code=404)
        if not vulnerable:
            if path == "app.js.map":
                return Response(
                    json.dumps(
                        {
                            "version": 3,
                            "sources": ["public.js"],
                            "sourcesContent": ["console.log('public')"],
                        }
                    ),
                    media_type="application/json",
                )
            if path in {"actuator/env", "actuator/configprops"}:
                return Response(
                    json.dumps(
                        {
                            "propertySources": [
                                {"properties": {"database.password": {"value": "******"}}}
                            ]
                        }
                    ),
                    media_type="application/json",
                )
            return Response("<html>Login</html>", media_type="text/html", status_code=404)
        value = routes.get("/" + path)
        return (
            Response(value[0], media_type=value[1])
            if value
            else Response("not found", status_code=404)
        )

    return app


app = create_app()
