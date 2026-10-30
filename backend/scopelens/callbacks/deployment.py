"""Build the trusted callback runtime from explicit operator configuration."""

from scopelens.callbacks.runtime import create_callback_runtime
from scopelens.persistence.session import get_session_factory


def runtime_from_settings(settings, *, session_factory=None):
    if not settings.callback_collector_origins or not settings.callback_signing_key:
        return None
    return create_callback_runtime(
        session_factory or get_session_factory(settings),
        collector_origins=set(settings.callback_collector_origins),
        signing_key=settings.callback_signing_key.get_secret_value().encode(),
    )
