import requests
import logging
from http import HTTPStatus
from typing import Dict, Any, List, Literal
from .config import Config
from .exceptions import (
    TokenInvalidError,
    InvalidRequestError,
    NotAuthorizedException,
)
from .context import ContextCallerForward
from .services.iam import IAM
from .domain.client_repository import ClientRepository, LogLevel

logger = logging.getLogger(__name__)


class Client(ClientRepository):
    def __init__(self, **kargs) -> None:
        self.config = Config(**kargs)
        self._api_access_key = None
        self._api_secret_key = None
        self._validate_ssl = True
        self._region = ""
        self._service = ""
        self._token = ""
        self._log_level: LogLevel = "INFO"

    @property
    def iam(self):
        return IAM(self)

    @property
    def token(self):
        return self._token

    def get_log_level(self) -> LogLevel:
        return self._log_level

    def get_config(self):
        return self.config

    def get_token(self) -> str:
        return self._token

    def get_validate_ssl(self) -> bool:
        return self._validate_ssl

    def set_log_level(
        self,
        level: LogLevel,
    ):
        self._log_level = level
        logger.setLevel(level)

    def set_token(self, current_token: str):
        self._token = current_token
        return self

    def client(
        self,
        api_access_key=None,
        api_secret_key=None,
        validate_ssl=True,
    ):
        self._api_access_key = api_access_key
        self._api_secret_key = api_secret_key
        self._validate_ssl = validate_ssl
        return self

    def login(self, region="", service=""):
        """
        Authenticate user

        :param region: which region to set scope for this session
        :param service: which service to set scope for this session
        """
        url = f"{self.config.get_endpoint_authn()}/login"

        payload = {
            "username": self._api_access_key,
            "password": self._api_secret_key,
        }
        if service:
            payload["service"] = service
        if region:
            payload["region"] = region

        logger.debug("Body request: %s", payload)

        resp = requests.post(url, json=payload, verify=self._validate_ssl)

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        data = self.validate_api_response("login", resp)["data"]

        self._token = data["access_token"]
        self._expires_in = data["expires_in"]

        return self

    def assume_role(self, role_name="", tenant="", service="", region=""):
        """
        Assume one role, which the user is authorized to use it.

        The user must be authenticated first to assume role.

        If the user does not have the permission, raises NotAuthorizedException

        :param role_name: which role to use
        :param tenant: which tenant this role is from
        :param region: which region to set scope for this session
        :param service: which service to set scope for this session
        """
        url = f"{self.config.get_endpoint_authn()}/login/assumerole"

        payload = {
            "role": role_name,
            "tenant": tenant,
        }

        if service:
            payload["service"] = service
        if region:
            payload["region"] = region

        logger.debug("requesting assume role")
        logger.debug("Body request: %s", payload)

        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self._token}"},
            verify=self._validate_ssl,
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        data = self.validate_api_response("assume role", resp)["data"]

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

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        roles = self.validate_api_response("my roles", resp)["data"]["roles"]

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

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        return self.validate_api_response("token_validate", resp)["data"]

    def is_authorized_to_call_action_with_context(
        self,
        caller: ContextCallerForward,
        action: str,
        resource: str,
        additional_context: Dict[str, Any] = {},
        is_resource_policy: bool = False,
    ) -> Dict[str, Any]:
        """
        Request if the caller making the request, is authorized.

        :param caller: the required headers to forward
        :param action: the permission to check the action
        :resource: which resource it is been requested
        :additional_context: optional parameters to validate the permission, for example mfa enabled, region
        :is_resource_policy: if the policy is a resource policy

        Returns: a dict containing if the user is allowed (decision), and which policy matched

        Example:
        {
            "decision": "Allow" | "Deny"
            "diagnostics": {
                "reason": [
                    "policy_id" || None // when null, no policies were found
                ],
                "errors": []
            }
        }
        """
        path = "resource/is_authorized" if is_resource_policy else "is_authorized"
        url = f"{self.config.get_endpoint_authz()}/{path}"
        headers = {
            "Authorization": f"Bearer {self._token}",
        }
        payload = {
            "action": action,
            "resource": resource,
            "context": additional_context,
        }

        # parameter "requestedRegion" is required
        if payload["context"].get("requestedRegion") is None:
            payload["context"]["requestedRegion"] = ""

        logger.debug("validating the context parameters")
        caller.validate()
        headers_forward = caller.mount_header()

        # merge headers
        headers = {**headers, **headers_forward}

        logger.debug("Request headers: %s", headers)
        logger.debug("Request body: %s", payload)

        resp = requests.post(
            url,
            headers=headers,
            json=payload,
            verify=self._validate_ssl,
        )

        logger.debug("Header response: %s %s", resp.status_code, resp.headers)
        logger.debug("Body response:")
        logger.debug(resp.text)

        response = self.validate_api_response("token_validate", resp)
        return response

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

        Returns: boolean if the user is authorized
        """
        return (
            self.is_authorized_to_call_action_with_context(
                caller=caller,
                action=action,
                resource=resource,
                additional_context=additional_context,
            )["decision"]
            == "Allow"
        )

    def is_resource_authorized_to_call_action_with_context(
        self,
        caller: ContextCallerForward,
        action: str,
        resource: str,
        additional_context: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        """
        Request if the caller making the request, is resource authorized.

        :param caller: the required headers to forward
        :param action: the permission to check the action
        :resource: which resource it is been requested
        :additional_context: optional parameters to validate the permission, for example mfa enabled, region

        Returns: a dict containing if the user is allowed (decision), and which policy matched

        Example:
        {
            "decision": "Allow" | "Deny"
            "diagnostics": {
                "reason": [
                    "policy_id" || None // when null, no policies were found
                ],
                "errors": []
            }
        }
        """
        return self.is_authorized_to_call_action_with_context(
            caller=caller,
            action=action,
            resource=resource,
            additional_context=additional_context,
            is_resource_policy=True,
        )

    def is_resource_authorized_to_call_action(
        self,
        caller: ContextCallerForward,
        action: str,
        resource: str,
        additional_context: Dict[str, Any] = {},
    ) -> bool:
        """
        Request if the caller making the request, is resource authorized.

        :param caller: the required headers to forward
        :param action: the permission to check the action
        :resource: which resource it is been requested
        :additional_context: optional parameters to validate the permission, for example mfa enabled, region

        Returns: boolean if the user is authorized
        """
        return (
            self.is_resource_authorized_to_call_action_with_context(
                caller=caller,
                action=action,
                resource=resource,
                additional_context=additional_context,
            )["decision"]
            == "Allow"
        )

    def validate_api_response(
        self, api_name: str, resp: requests.Response
    ) -> Dict[str, Any]:
        """
        Validate the API response, checking the possible errors.

        When the request is successful, returns the JSON response

        :param api_name: the endpoint been validated
        :param resp: the requests.Response
        """
        logger.debug('validate "%s" response', api_name)

        api_status_code = resp.status_code
        api_response_text = resp.text

        # validate if the api is not 2XX
        if api_status_code >= 400 or api_status_code >= 500:
            logger.debug(f"{api_name=}, {api_status_code=}, {api_response_text=}")

            if api_status_code == HTTPStatus.UNAUTHORIZED:
                raise TokenInvalidError()

            if api_status_code == HTTPStatus.FORBIDDEN:
                raise NotAuthorizedException(message=api_response_text)

            raise InvalidRequestError(
                status_code=api_status_code, message=api_response_text
            )

        return resp.json()
