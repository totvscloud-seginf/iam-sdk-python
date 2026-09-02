import base64
import json
import os
import unittest
from unittest.mock import patch

from tests.patches import api as patch_api
from tests.patches.http import FakeObject

import iam_sdk
from iam_sdk.context import ContextCallerForward
from iam_sdk.identity import (
    LOG_CALLER_IDENTITY_ENV,
    decode_jwt_payload,
    token_ext_claims,
)


def build_jwt(claims):
    """A JWT with a real payload - the signature is irrelevant here."""

    def segment(data):
        raw = base64.urlsafe_b64encode(json.dumps(data).encode())
        return raw.rstrip(b"=").decode()

    return "{}.{}.{}".format(
        segment({"alg": "HS256", "typ": "JWT"}), segment(claims), "not-a-signature"
    )


EXT = {
    "username": "userapi",
    "email": "luser@totvs.com.br",
    "tenant": "cseinf",
    "principal": 'trn::tcloud::iam::::cseinf::user::"userapi"',
    "mfa": "active",
}

TOKEN = build_jwt({"sub": "d517a500", "exp": 1699027892, "ext": EXT})


def mock_post_login_jwt(url, **kargs):
    """Login mock returning a decodable JWT."""
    if url.endswith("/login"):
        response = json.dumps(
            {
                "data": {
                    "access_token": TOKEN,
                    "expires_in": 3599,
                    "token_type": "bearer",
                },
                "error": False,
                "message": "success",
            }
        )
        return FakeObject(
            response=response,
            status_code=200,
            headers={"content-type": "application/json"},
        )

    raise Exception("endpoint mock not found")


class TestDecodeJwt(unittest.TestCase):
    def test_decodes_the_payload(self):
        claims = decode_jwt_payload(TOKEN)

        self.assertEqual(claims["sub"], "d517a500")
        self.assertEqual(claims["ext"], EXT)

    def test_handles_payload_without_base64_padding(self):
        # exercises every possible padding length
        for size in range(1, 5):
            token = build_jwt({"ext": {"username": "u" * size}})
            self.assertEqual(
                token_ext_claims(token)["username"], "u" * size, "size %d" % size
            )

    def test_returns_empty_for_invalid_tokens(self):
        for token in (None, "", "not-a-jwt", "a.b", 42, "a." + "!" * 10 + ".c"):
            self.assertEqual(decode_jwt_payload(token), {}, repr(token))

    def test_returns_empty_when_there_is_no_ext_claim(self):
        self.assertEqual(token_ext_claims(build_jwt({"sub": "x"})), {})

    def test_returns_empty_when_ext_is_not_an_object(self):
        self.assertEqual(token_ext_claims(build_jwt({"ext": "nope"})), {})


class TestCallerIdentityLogging(unittest.TestCase):
    def _caller(self):
        return ContextCallerForward(
            caller_token_jwt=TOKEN,
            caller_source_ip="192.0.0.1",
            caller_user_agent="Mozilla/5.0",
            caller_referer="localhost",
            caller_resource_tenant="cseinf",
        )

    @patch("iam_sdk.api.requests.post", mock_post_login_jwt)
    def test_login_logs_who_authenticated(self):
        with patch.dict(os.environ, {}, clear=True):
            client = iam_sdk.client(
                api_access_key="userapi",
                api_secret_key="secret",
                log_caller_identity=True,
            )
            with self.assertLogs("iam_sdk.api", level="INFO") as logs:
                client.login()

        output = "\n".join(logs.output)
        self.assertIn("login requested by", output)
        self.assertIn("luser@totvs.com.br", output)
        # the token is still never logged
        self.assertNotIn(TOKEN, output)

    @patch("iam_sdk.api.requests.post", mock_post_login_jwt)
    def test_disabled_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            client = iam_sdk.client(
                api_access_key="userapi", api_secret_key="secret"
            )
            with self.assertLogs("iam_sdk.api", level="DEBUG") as logs:
                client.login()

        output = "\n".join(logs.output)
        self.assertNotIn("requested by", output)
        self.assertNotIn("luser@totvs.com.br", output)

    @patch("iam_sdk.api.requests.post", mock_post_login_jwt)
    def test_enabled_by_env_var(self):
        with patch.dict(os.environ, {LOG_CALLER_IDENTITY_ENV: "true"}):
            client = iam_sdk.client(
                api_access_key="userapi", api_secret_key="secret"
            )
            with self.assertLogs("iam_sdk.api", level="INFO") as logs:
                client.login()

        self.assertIn("login requested by", "\n".join(logs.output))

    @patch("iam_sdk.api.requests.post", patch_api.mock_post)
    def test_is_authorized_logs_the_caller_not_the_session(self):
        with patch.dict(os.environ, {}, clear=True):
            client = iam_sdk.client(log_caller_identity=True)
            with self.assertLogs("iam_sdk.api", level="INFO") as logs:
                client.is_authorized_to_call_action(
                    caller=self._caller(),
                    action='Service::Nostromos::Action::"CreateDatabase2"',
                    resource='Database::"Mysql"',
                    additional_context={"requestedRegion": "tesp1"},
                )

        output = "\n".join(logs.output)
        self.assertIn("CreateDatabase2", output)
        self.assertIn('Database::"Mysql"', output)
        self.assertIn("luser@totvs.com.br", output)
        self.assertNotIn(TOKEN, output)

    @patch("iam_sdk.api.requests.post", patch_api.mock_post)
    def test_non_decodable_token_does_not_break_the_request(self):
        """mock_post returns the opaque "token jwt" as access_token."""
        with patch.dict(os.environ, {}, clear=True):
            client = iam_sdk.client(
                api_access_key="userapi",
                api_secret_key="secret",
                log_caller_identity=True,
            )
            client.login()

        self.assertEqual(client.token, "token jwt")


if __name__ == "__main__":
    unittest.main()
