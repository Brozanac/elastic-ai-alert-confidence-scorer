import os

from dotenv import load_dotenv
from errors import unauthorized
from fastapi import Header

load_dotenv()


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    expected_api_key = os.getenv("APP_API_KEY")

    if not expected_api_key:
        return

    if x_api_key != expected_api_key:
        raise unauthorized("Invalid or missing API key.")