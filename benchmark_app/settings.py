from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "LLM Benchmark Dashboard"
    open_source_url: str
    results_root: str
    static_dir: str = "static"
    templates_dir: str = "templates"
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
