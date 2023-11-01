import requests
from typing import Dict, Any, List
from .config import Config
from .exceptions import (
    TokenInvalidError,
    NotAuthenticatedException,
)


class Client:
    def __init__(self, **kargs) -> None:
        self.config = Config(**kargs)
        self._api_access_key = None
        self._api_secret_key = None
        self._validate_ssl = True
        self._region = ""
        self._service = ""
        self._token = ""
        self._expires_in = 0

    @property
    def token(self):
        return self._token

    def client(
        self,
        api_access_key=None,
        api_secret_key=None,
        validate_ssl=True,
        region=None,
        service=None,
    ):
        self._api_access_key = api_access_key
        self._api_secret_key = api_secret_key
        self._validate_ssl = validate_ssl
        self._region = region
        self._service = service
        return self

    def _is_authenticated(func):
        def inner(self, *args, **kwargs):
            if self._token is None or self._token == "":
                raise NotAuthenticatedException(
                    "to use this api, you must be authenticated"
                )

            return func(self, *args, **kwargs)

        return inner

    def login(self):
        url = f"{self.config.get_endpoint()}/login"

        form = {
            "username": self._api_access_key,
            "password": self._api_secret_key,
        }
        if self._service:
            form["service"] = self._service
        if self._region:
            form["region"] = self._region

        resp = requests.post(url, json=form, verify=self._validate_ssl)

        if resp.status_code != 200:
            raise Exception(f"invalid payload, err={resp.text}")

        data = resp.json()
        self._token = data["data"]["access_token"]
        self._expires_in = data["data"]["expires_in"]

        return self

    @_is_authenticated
    def assume_role(self, role_name="", tenant=""):
        url = f"{self.config.get_endpoint()}/login/assumerole"

        form = {
            "role": role_name,
            "tenant": tenant,
        }
        if self._service:
            form["service"] = self._service
        if self._region:
            form["region"] = self._region

        resp = requests.post(url, json=form, verify=self._validate_ssl)

        if resp.status_code != 200:
            raise Exception(f"invalid payload, err={resp.text}")

        data = resp.json()
        self._token = data["data"]["access_token"]
        self._expires_in = data["data"]["expires_in"]

        return self

    @_is_authenticated
    def list_my_roles(self) -> List[Dict[str, Any]]:
        url = f"{self.config.get_endpoint()}/me/roles"

        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {self._token}"},
            verify=self._validate_ssl,
        )

        if resp.status_code != 200:
            raise TokenInvalidError(f"invalid token, error={resp.text}")

        roles = resp.json()["data"]["roles"]

        return roles

    def validate_token(self) -> Dict[str, Any]:
        url = f"{self.config.get_endpoint()}/oauth2/introspection"

        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {self._token}"},
            verify=self._validate_ssl,
        )

        if resp.status_code != 200:
            raise TokenInvalidError(f"invalid token, error={resp.text}")

        info = resp.json()["data"]

        return info
