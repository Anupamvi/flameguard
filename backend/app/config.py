import json
from ipaddress import IPv4Network, IPv6Network, ip_network
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
    cors_origins: str = '["http://localhost:3000"]'
    llm_model: str = "gpt-5.4-nano"
    max_rules_per_chunk: int = 50
    max_log_rules_for_analysis: int = 200
    upload_max_size_mb: int = 50
    rate_limit_enabled: bool = True
    trust_proxy_headers: bool = True
    trusted_proxy_cidrs: str = "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16,fc00::/7,fe80::/10"
    front_door_origin_token: str = ""
    upload_rate_limit_requests: int = 10
    upload_rate_limit_window_seconds: int = 600
    generation_rate_limit_requests: int = 20
    generation_rate_limit_window_seconds: int = 600
    chat_rate_limit_requests: int = 12
    chat_rate_limit_window_seconds: int = 600
    read_rate_limit_requests: int = 240
    read_rate_limit_window_seconds: int = 60
    admin_mutation_rate_limit_requests: int = 10
    admin_mutation_rate_limit_window_seconds: int = 300
    max_concurrent_audit_jobs: int = 2
    admin_api_token: str = ""

    @property
    def parsed_cors_origins(self) -> list[str]:
        raw_value = self.cors_origins.strip()
        if not raw_value:
            return []

        if raw_value.startswith("[") and raw_value.endswith("]"):
            try:
                parsed_value = json.loads(raw_value)
            except json.JSONDecodeError:
                raw_value = raw_value[1:-1]
            else:
                if isinstance(parsed_value, list):
                    return [str(origin).strip() for origin in parsed_value if str(origin).strip()]
                parsed_item = str(parsed_value).strip()
                return [parsed_item] if parsed_item else []

        origins = [part.strip().strip('"').strip("'") for part in raw_value.split(",")]
        return [origin for origin in origins if origin]

    @property
    def parsed_trusted_proxy_networks(self) -> list[IPv4Network | IPv6Network]:
        networks: list[IPv4Network | IPv6Network] = []
        for value in self.trusted_proxy_cidrs.split(","):
            cidr = value.strip()
            if not cidr:
                continue
            try:
                networks.append(ip_network(cidr, strict=False))
            except ValueError:
                continue
        return networks

    model_config = {"env_file": ".env", "env_prefix": "", "case_sensitive": False}


settings = Settings()
