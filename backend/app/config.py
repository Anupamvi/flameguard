from typing import Literal

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # LLM provider: "openai" (direct OpenAI API) or "azure" (Azure AI Foundry)
    llm_provider: Literal["openai", "azure"] = "azure"

    # OpenAI direct API settings
    openai_api_key: str = ""

    # Azure AI Foundry settings (used when llm_provider="azure")
    azure_endpoint: str = ""       # e.g. https://<resource>.services.ai.azure.com
    azure_api_key: str = ""        # Azure API key
    azure_api_version: str = "2024-12-01-preview"

    # Common settings
    db_path: str = "./data/flameguard.db"
    cors_origins: list[str] = ["http://localhost:3000"]
    llm_model: str = "gpt-5.4-nano"
    max_rules_per_chunk: int = 50
    upload_max_size_mb: int = 50

    model_config = {"env_file": ".env", "env_prefix": "", "case_sensitive": False}


settings = Settings()
