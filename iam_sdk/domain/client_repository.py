from abc import ABC
from typing import Any, Literal

LogLevel = Literal[
    "CRITICAL",
    "ERROR",
    "WARNING",
    "INFO",
    "DEBUG",
    "NOTSET",
]


class ClientRepository(ABC):
    def get_log_level(self) -> LogLevel:
        raise NotImplementedError("get_log_level not implemented")

    def get_config(self):
        raise NotImplementedError("get_config not implemented")

    def get_token(self) -> str:
        raise NotImplementedError("get_token not implemented")

    def get_validate_ssl(self) -> bool:
        raise NotImplementedError("get_validate_ssl not implemented")

    def validate_api_response(self, api_name: str, resp_http: Any) -> Any:
        raise NotImplementedError("validate_api_response not implemented")
