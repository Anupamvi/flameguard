from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    anthropic_api_key: str = ""
    db_path: str = "./data/flameguard.db"
    cors_origins: list[str] = ["http://localhost:3000"]
    claude_model: str = "claude-sonnet-4-20250514"
    max_rules_per_chunk: int = 50
    upload_max_size_mb: int = 50

    model_config = {"env_file": ".env", "env_prefix": "", "case_sensitive": False}


settings = Settings()
