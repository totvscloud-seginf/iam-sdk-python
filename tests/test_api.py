import unittest
import traceback
from unittest.mock import patch

from tests.patches import api as patch_api

import iam_sdk
from iam_sdk.context import ContextCallerForward

# import logging
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)


class TestApi(unittest.TestCase):
    def test_valid_client_parameters(self):
        try:
            _ = iam_sdk.client(
                endpoint_authn="http://123:80",
                endpoint_authz="http://123:80",
                api_access_key="a",
                api_secret_key="a",
                validate_ssl=False,
            )

            _ = iam_sdk.client()

            _ = iam_sdk.Client().client()

        except Exception:
            self.fail(
                f"client() got exception when testing parameters: {traceback.format_exc()}"
            )

    @patch("iam_sdk.api.requests.get", patch_api.mock_get)
    @patch("iam_sdk.api.requests.post", patch_api.mock_post)
    def test_get_roles(self):
        client = iam_sdk.client()

        try:
            roles = client.list_my_roles()
            self.assertGreater(len(roles), 0, "mocked roles is empty")
        except Exception:
            self.fail(f"list_my_roles() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_get)
    def test_validate_token(self):
        try:
            _ = iam_sdk.client().validate_token()
        except Exception:
            self.fail(f"validate_token() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.get", patch_api.mock_get_invalid_token)
    def test_validate_token_invalid(self):
        with self.assertRaises(iam_sdk.exceptions.TokenInvalidError):
            _ = iam_sdk.client().validate_token()

    @patch("iam_sdk.api.requests.post", patch_api.mock_post)
    def test_login(self):
        client = iam_sdk.client(
            api_access_key="user",
            api_secret_key="password",
        )

        try:
            _ = client.login(region="aaa", service="aaa")
        except Exception:
            self.fail(f"login() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.post", patch_api.mock_post_login_invalid)
    def test_login_invalid_credentials(self):
        client = iam_sdk.client(
            api_access_key="user",
            api_secret_key="invalid",
        )

        with self.assertRaises(iam_sdk.exceptions.InvalidRequestError):
            _ = client.login()

    @patch("iam_sdk.api.requests.post", patch_api.mock_post_assumerole)
    def test_assume_role(self):
        client = iam_sdk.client(
            api_access_key="user", api_secret_key="password"
        ).login()

        try:
            client.assume_role(
                role_name="role",
                tenant="test",
            )
        except Exception:
            self.fail(f"assume_role() got exception: {traceback.format_exc()}")

    @patch("iam_sdk.api.requests.post", patch_api.mock_post_assumerole_forbidden)
    def test_assume_role_forbidden(self):
        client = iam_sdk.client(
            api_access_key="user", api_secret_key="password"
        ).login()

        with self.assertRaises(iam_sdk.exceptions.NotAuthorizedException):
            _ = client.assume_role(
                role_name="role",
                tenant="test",
            )

    @patch("iam_sdk.api.requests.post", patch_api.mock_post)
    def test_is_authorized(self):
        client = iam_sdk.client()

        caller_context = ContextCallerForward(
            caller_token_jwt="eyJhbGciOiJIUzI1NiIsImtpZCI6IjgzN2IxZDU5LTRiZTktNDg1OS1iNzhlLTMxNWY4OTAwMWNmMCIsInR5cCI6IkpXVCJ9.eyJhdWQiOltdLCJleHAiOjE2OTI3MjkxMjYsImV4dCI6eyJwcmluY2lwYWwiOiJ0Y2xvdWQ6OnRlbmFudDo6Q0NPREUwOjpyb2xlOjpcInJvbGVfcml2YXNhbmRyZVwiIiwicmVnaW9uIjoidGVzcDIiLCJzZXJ2aWNlIjoicm9kanVsIiwidGVuYW50IjoiQ0NPREUwIiwidXNlcl9pZCI6IjI4NTc3NzM0LWZyMTktNGM2NS05ODg3LWM1YjY2NjM0NjlkMyIsInVzZXJuYW1lIjoidXNlcmFwaSIsIm1mYSI6ImFjdGl2ZSJ9LCJpYXQiOjE2OTI3MjU1MjYsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NDQ0NCIsImp0aSI6IjI2MzFhYjRhLTc1ZTgtNDUwOS1iOGRhLTBlZTJkMTRiNzM0OCIsIm5iZiI6MTY5MjcyNTUyNiwicmVnaW9uIjoidGVzcDIiLCJzY3AiOltdLCJzZXJ2aWNlIjoicmVzdHJpY3Rpb25zIiwic3ViIjoiM2FkZWVlODItZjFjNy00MzJiLTg0MjQtYzhlYjFkNzQ1NTNlIn0.x5sSsBcxYNMEClAcJIFngdkZRY6H-v8Dt72Vn1pI2Uc",
            caller_source_ip="192.0.0.1",
            caller_user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
            caller_referer="localhost",
            caller_resource_tenant="CCODE9",
        )

        action = 'Service::Nostromos::Action::"CreateDatabase2"'
        resource = 'Database::"Mysql"'
        additional_context = {"requestedRegion": "tesp1"}

        try:
            client.is_authorized_to_call_action(
                caller=caller_context,
                action=action,
                resource=resource,
                additional_context=additional_context,
            )
        except Exception:
            self.fail(
                f"is_authorized_to_call_action() got exception: {traceback.format_exc()}"
            )

    def test_caller_context_requirement_for_is_authorized(self):
        client = iam_sdk.client()

        caller_context = ContextCallerForward()

        with self.assertRaises(ValueError):
            client.is_authorized_to_call_action(caller_context, "", "")

        try:
            caller_context.set_caller_referer("value")
            caller_context.set_caller_resource_tenant("value")
            caller_context.set_caller_source_ip("value")
            caller_context.set_caller_token_jwt("value")
            caller_context.set_caller_user_agent("value")
        except Exception:
            self.fail(
                f"expected setters for ContextCallerForward got exception: {traceback.format_exc()}"
            )

        try:
            caller_context.validate()

            ContextCallerForward(
                caller_token_jwt="a",
                caller_source_ip="a",
                caller_user_agent="a",
                caller_referer="a",
                caller_resource_tenant="a",
            ).validate()
        except Exception:
            self.fail(
                f"ContextCallerForward.validate() got exception when all parameters are set: {traceback.format_exc()}"
            )
