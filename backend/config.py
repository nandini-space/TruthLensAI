"""Minimal environment-backed configuration for future backend integrations."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _optional_env(name: str) -> str | None:
    """Return a non-empty environment value without loading files or secrets."""

    value = os.getenv(name)
    return value if value else None


@dataclass(frozen=True, slots=True)
class Settings:
    """Configuration names already documented in ``.env.example``.

    This class deliberately does not connect to external services or read a .env
    file. Deployment tooling may populate the process environment before calling
    :meth:`from_environment`.
    """

    app_env: str | None
    app_host: str | None
    app_port: str | None
    supabase_url: str | None
    supabase_anon_key: str | None
    supabase_service_role_key: str | None
    virustotal_api_key: str | None

    @classmethod
    def from_environment(cls) -> Settings:
        return cls(
            app_env=_optional_env("APP_ENV"),
            app_host=_optional_env("APP_HOST"),
            app_port=_optional_env("APP_PORT"),
            supabase_url=_optional_env("SUPABASE_URL"),
            supabase_anon_key=_optional_env("SUPABASE_ANON_KEY"),
            supabase_service_role_key=_optional_env("SUPABASE_SERVICE_ROLE_KEY"),
            virustotal_api_key=_optional_env("VIRUSTOTAL_API_KEY"),
        )
