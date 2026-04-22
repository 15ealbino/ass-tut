from pydantic import field_validator
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/asstut"
    SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24

    @field_validator('SECRET_KEY')
    @classmethod
    def secret_key_must_be_set(cls, v: str) -> str:
        if not v or v == "change-me-in-production":
            raise ValueError("SECRET_KEY must be set to a secure random value")
        return v

    class Config:
        env_file = ".env"

settings = Settings()
