import requests
import logging
from http import HTTPStatus
from typing import Dict, Any, List
from .config import Config
from .exceptions import (
    TokenInvalidError,
    InvalidRequestError,
    NotAuthorizedException,
)
from .context import ContextCallerForward

logger = logging.getLogger(__name__)


class Client:
    def __init__(self, **kargs) -> None:
        self.config = Config(**kargs)
        self._api_access_key = None
        self._api_secret_key = None
        self._validate_ssl = True
        self._region = ""
        self._service = ""
        self._token = ""

    @property
    def token(self):
        return self._token

    def set_token(self, current_token: str):
        self._token = current_token
        return self

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

    def login(self):
        """
        Authenticate user
        """
        url = f"{self.config.get_endpoint_authn()}/login"

        form = {
            "username": self._api_access_key,
            "password": self._api_secret_key,
        }
        if self._service:
            form["service"] = self._service
        if self._region:
            form["region"] = self._region

        resp = requests.post(url, json=form, verify=self._validate_ssl)

        data = self._validate_api_response("login", resp)["data"]

        self._token = data["access_token"]
        self._expires_in = data["expires_in"]

        return self

    def assume_role(self, role_name="", tenant=""):
        """
        Assume one role, which the user is authorized to use it.

        The user must be authenticated first to assume role.

        If the user does not have the permission, raises NotAuthorizedException
        """
        url = f"{self.config.get_endpoint_authn()}/login/assumerole"

        form = {
            "role": role_name,
            "tenant": tenant,
        }

        if self._service:
            form["service"] = self._service
        if self._region:
            form["region"] = self._region

        logger.debug("requesting assume role")

        resp = requests.post(
            url,
            json=form,
            headers={"Authorization": f"Bearer {self._token}"},
            verify=self._validate_ssl,
        )

        data = self._validate_api_response("assume role", resp)["data"]

        self._token = data["access_token"]
        self._expires_in = data["expires_in"]

        return self

    def list_my_roles(self) -> List[Dict[str, Any]]:
        """
        Get roles authorized to assume role.
        """
        url = f"{self.config.get_endpoint_authn()}/me/roles"

        logger.info("requesting user roles")

        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {self._token}"},
            verify=self._validate_ssl,
        )

        roles = self._validate_api_response("my roles", resp)["data"]["roles"]

        return roles

    def validate_token(self) -> Dict[str, Any]:
        """
        Request the current token status.

        When the token is invalid / expired, raises TokenInvalidError

        Returns the claims of token
        """
        url = f"{self.config.get_endpoint_authn()}/token/validate"

        logger.debug("requesting validate token")

        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {self._token}"},
            verify=self._validate_ssl,
        )

        return self._validate_api_response("token_validate", resp)["data"]

    def is_authorized_to_call_action(
        self,
        caller: ContextCallerForward,
        action: str,
        resource: str,
        additional_context: Dict[str, Any] = {},
    ) -> bool:
        """
        Request if the caller making the request, is authorized.

        :param caller: the required headers to forward
        :param action: the permission to check the action
        :resource: which resource it is been requested
        :additional_context: optional parameters to validate the permission, for example mfa enabled, region
        """
        url = f"{self.config.get_endpoint_authz()}/is_authorized"
        headers = {
            "Authorization": f"Bearer {self._token}",
        }
        payload = {
            "action": action,
            "resource": resource,
        }

        if additional_context:
            payload["context"] = additional_context

        logger.debug("requesting validate token")

        logger.debug("validating the context parameters")
        caller.validate()

        headers_forward = caller.mount_header()

        # merge headers
        headers = {**headers, **headers_forward}

        resp = requests.post(
            url,
            headers=headers,
            json=payload,
            verify=self._validate_ssl,
        )

        response = self._validate_api_response("token_validate", resp)
        return response["decision"] == "Allow"

    def _validate_api_response(
        self, api_name: str, resp: requests.Response
    ) -> Dict[str, Any]:
        """
        Validate the API response, checking the possible errors.

        When the request is successful, returns the JSON response

        :param api_name: the endpoint been validated
        :param resp: the requests.Response
        """
        logger.debug("validate %s response", api_name)

        api_status_code = resp.status_code
        api_response_text = resp.text

        # validate if the api is not 2XX
        if api_status_code >= 400 or api_status_code >= 500:
            logger.error("%s contains invalid response", api_name)

            if api_status_code == HTTPStatus.UNAUTHORIZED:
                raise TokenInvalidError()

            if api_status_code == HTTPStatus.FORBIDDEN:
                raise NotAuthorizedException(message=api_response_text)

            if (
                api_status_code == HTTPStatus.BAD_REQUEST
                or api_status_code >= HTTPStatus.INTERNAL_SERVER_ERROR
            ):
                raise InvalidRequestError(
                    status_code=api_status_code, message=api_response_text
                )

        return resp.json()
