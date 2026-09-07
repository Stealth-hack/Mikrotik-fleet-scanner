from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Falls back to local SQLite if no Postgres URL is set — fine for early dev,
    # switch to Postgres before you're testing against more than a couple devices.
    database_url: str = "sqlite:///./fleet_scanner.db"

    credential_encryption_key: str = ""

    chr_host: str = "192.168.56.10"
    chr_port: int = 8728
    chr_user: str = "admin"
    chr_password: str = ""


settings = Settings()
