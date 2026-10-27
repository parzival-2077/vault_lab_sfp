from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite:///./vault.db"

    password_pepper: str
    password_min_length: int = 12

    environment: str = "development"
    app_name: str = "Vault"

    redis_url: str = "redis://localhost:6379/0"
    issuer: str = "http://127.0.0.1:8000"

    rsa_key_path: str = "./keys/rsa_private.pem"
    rsa_key_id: str = "vault-key-1"

    access_token_ttl_sec: int = 900
    refresh_token_ttl_days: int = 30
    auth_code_ttl_sec: int = 60
    pkce_required_for_public: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore"
    )


settings = Settings()