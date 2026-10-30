"""Optional dedicated receipt receiver. No operator or control routes are mounted."""

from fastapi import FastAPI

from scopelens.callbacks.deployment import runtime_from_settings
from scopelens.callbacks.service import callback_router
from scopelens.config import get_settings


def create_callback_app(settings=None, *, runtime=None) -> FastAPI:
    runtime = runtime or runtime_from_settings(settings or get_settings())
    if runtime is None:
        raise RuntimeError("callback receiver requires explicit collector origins and signing key")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(callback_router(runtime.service))

    @app.get("/healthz", include_in_schema=False)
    def health():
        return {"status": "ok"}

    return app
