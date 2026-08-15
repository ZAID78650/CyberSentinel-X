"""Application configuration loaded from environment variables."""
from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application settings. Values come from the environment / .env file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    app_name: str = "CyberSentinel X"
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    # Database
    database_url: str = "sqlite:///../data/cybersentinel.db"

    # Auth
    jwt_secret: str = "dev-only-insecure-secret-change-me"
    jwt_refresh_secret: str = "dev-only-insecure-refresh-secret-change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # LLM
    llm_provider: str = "local"  # local | openai | gemini
    openai_api_key: str = ""
    gemini_api_key: str = ""
    llm_model: str = "gpt-4o-mini"

    # OAuth / social login (empty = SSO buttons show as unconfigured)
    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""

    # SMTP email (empty password = email disabled, degrades gracefully)
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    email_from: str = ""
    ops_email: str = ""

    # Docker Hub (used by scripts/push-dockerhub.sh)
    docker_registry: str = "fs22ai006/cybersentinel-x"

    # UNSW-NB15 dataset
    unsw_dataset_dir: str = ""  # directory containing the *_set.csv files
    unsw_ingest_limit: int = 0  # 0 = ingest everything

    # Dataset uploads (analyst-provided CSVs)
    dataset_upload_dir: str = "../data/uploads"

    # Vector store
    vector_db_backend: str = "local"  # local | chroma
    vector_db_path: str = "./data/vector_store"

    # CORS / URLs
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    frontend_url: str = "http://localhost:5173"
    backend_url: str = "http://localhost:8000"

    # Rate limiting (requests per window per key)
    rate_limit_max_requests: int = 20
    rate_limit_window_seconds: int = 60

    @property
    def unsw_dataset_paths(self) -> list[str]:
        """Resolve UNSW CSV paths from the configured directory.

        Only the labeled training-set / testing-set CSVs are ingested;
        the LIST_EVENTS reference CSV has a different schema.
        """
        import glob
        import os

        if not self.unsw_dataset_dir:
            return []
        return sorted(
            f for f in glob.glob(os.path.join(self.unsw_dataset_dir, "*.csv"))
            if "set.csv" in os.path.basename(f).lower()
        )

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in ("production", "prod")


@lru_cache
def get_settings() -> Settings:
    return Settings()
