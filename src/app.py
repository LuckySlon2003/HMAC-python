"""Module with FastAPI application"""

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError

from src.exceptions import request_validation_exception_handler
from src.logger import setup_logging
from src.router import router

setup_logging()

app = FastAPI()
app.add_exception_handler(
    RequestValidationError,
    request_validation_exception_handler,
)
app.include_router(router)
