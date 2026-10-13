from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_ttl_min: int = 60
    password_pepper: str
    password_min_length: int = 12
    environment: str = "development"
    app_name: str = "Vault"

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()