import json
import os
import unittest
from unittest.mock import patch

from tests.patches import api as patch_api

import iam_sdk
from iam_sdk.config import resolve_flag
from iam_sdk.redact import (
    REDACTED,
    UNSAFE_DEBUG_LOGGING_ENV,
    Redactor,
    redact_data,
    redact_text,
)

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJ1c2VybmFtZSI6InVzZXJhcGkiLCJ0ZW5hbnQiOiJDQ09ERTAifQ"
    ".x5sSsBcxYNMEClAcJIFngdkZRY6H-v8Dt72Vn1pI2Uc"
)


class TestRedactData(unittest.TestCase):
    def test_redacts_login_credentials(self):
        payload = {"username": "userapi", "password": "sup3r-s3cret"}

        redacted = redact_data(payload)

        self.assertEqual(redacted["password"], REDACTED)
        # the access key id stays readable, it is an identifier not a secret
        self.assertEqual(redacted["username"], "userapi")

    def test_redacts_authorization_and_caller_token_headers(self):
        headers = {
            "Authorization": f"Bearer {JWT}",
            "x-token-jwt": JWT,
            "x-source-ip": "192.0.0.1",
        }

        redacted = redact_data(headers)

        self.assertEqual(redacted["Authorization"], REDACTED)
        self.assertEqual(redacted["x-token-jwt"], REDACTED)
        self.assertEqual(redacted["x-source-ip"], "192.0.0.1")

    def test_key_matching_ignores_case_and_separators(self):
        redacted = redact_data(
            {"API_Secret_Key": "a", "Set-Cookie": "b", "accessToken": "c"}
        )

        self.assertEqual(list(redacted.values()), [REDACTED, REDACTED, REDACTED])

    def test_redacts_nested_structures(self):
        redacted = redact_data(
            {"data": {"users": [{"name": "u", "secretKey": "s"}]}},
        )

        self.assertEqual(redacted["data"]["users"][0]["secretKey"], REDACTED)
        self.assertEqual(redacted["data"]["users"][0]["name"], "u")

    def test_scrubs_tokens_under_non_sensitive_keys(self):
        redacted = redact_data({"note": f"used Bearer {JWT} to call"})

        self.assertNotIn(JWT, redacted["note"])

    def test_keeps_non_string_values(self):
        redacted = redact_data({"expires_in": 3600, "active": True, "aud": None})

        self.assertEqual(redacted, {"expires_in": 3600, "active": True, "aud": None})

    def test_does_not_mutate_the_original_payload(self):
        payload = {"password": "sup3r-s3cret"}

        redact_data(payload)

        self.assertEqual(payload["password"], "sup3r-s3cret")


class TestRedactText(unittest.TestCase):
    def test_redacts_login_response_body(self):
        body = json.dumps(
            {
                "data": {"access_token": JWT, "expires_in": 3600},
                "error": False,
            }
        )

        redacted = json.loads(redact_text(body))

        self.assertEqual(redacted["data"]["access_token"], REDACTED)
        # the rest of the body stays useful for debugging
        self.assertEqual(redacted["data"]["expires_in"], 3600)
        self.assertFalse(redacted["error"])

    def test_redacts_access_key_response_body(self):
        body = json.dumps({"data": {"accessKey": "AK123", "secretKey": "shhh"}})

        redacted = json.loads(redact_text(body))

        self.assertEqual(redacted["data"]["accessKey"], REDACTED)
        self.assertEqual(redacted["data"]["secretKey"], REDACTED)

    def test_scrubs_token_from_non_json_body(self):
        redacted = redact_text(f"<html>token {JWT}</html>")

        self.assertNotIn(JWT, redacted)
        self.assertIn(REDACTED, redacted)

    def test_keeps_plain_error_body(self):
        self.assertEqual(redact_text("invalid credentials"), "invalid credentials")

    def test_handles_empty_and_non_string(self):
        self.assertEqual(redact_text(""), "")
        self.assertIsNone(redact_text(None))


class TestRedactor(unittest.TestCase):
    def test_redacts_by_default_and_is_lazy(self):
        redactor = Redactor()
        wrapped = redactor.data({"password": "sup3r-s3cret"})

        # nothing is computed until the log record is formatted
        self.assertNotIsInstance(wrapped, dict)
        self.assertIn(REDACTED, "%s" % wrapped)
        self.assertNotIn("sup3r-s3cret", "%s" % wrapped)

    def test_unsafe_returns_the_real_value_and_warns(self):
        with self.assertLogs("iam_sdk.redact", level="WARNING") as logs:
            redactor = Redactor(unsafe=True)

        self.assertTrue(any("PLAINTEXT" in line for line in logs.output))
        self.assertTrue(redactor.unsafe)

        payload = {"password": "sup3r-s3cret"}
        self.assertIs(redactor.data(payload), payload)
        self.assertIn("sup3r-s3cret", "%s" % redactor.data(payload))


class TestUnsafeFlagResolution(unittest.TestCase):
    def test_defaults_to_false(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(resolve_flag(None, UNSAFE_DEBUG_LOGGING_ENV))

    def test_env_var_enables_it(self):
        for value in ("1", "true", "TRUE", "yes", "on"):
            with patch.dict(os.environ, {UNSAFE_DEBUG_LOGGING_ENV: value}):
                self.assertTrue(resolve_flag(None, UNSAFE_DEBUG_LOGGING_ENV), value)

        with patch.dict(os.environ, {UNSAFE_DEBUG_LOGGING_ENV: "no"}):
            self.assertFalse(resolve_flag(None, UNSAFE_DEBUG_LOGGING_ENV))

    def test_explicit_argument_wins_over_env_var(self):
        with patch.dict(os.environ, {UNSAFE_DEBUG_LOGGING_ENV: "true"}):
            self.assertFalse(resolve_flag(False, UNSAFE_DEBUG_LOGGING_ENV))

        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(resolve_flag(True, UNSAFE_DEBUG_LOGGING_ENV))


class TestClientDebugLogging(unittest.TestCase):
    """End to end: the credential must not reach the DEBUG log of login()."""

    PASSWORD = "dd16b129283964f76c0114b3dec93eed"

    def _login(self, **kargs):
        client = iam_sdk.client(
            api_access_key="userapi",
            api_secret_key=self.PASSWORD,
            **kargs,
        )
        with self.assertLogs("iam_sdk.api", level="DEBUG") as logs:
            client.login()
        return "\n".join(logs.output)

    @patch("iam_sdk.api.requests.post", patch_api.mock_post)
    def test_login_does_not_leak_the_secret_key(self):
        with patch.dict(os.environ, {}, clear=True):
            output = self._login()

        self.assertNotIn(self.PASSWORD, output)
        self.assertIn(REDACTED, output)

    @patch("iam_sdk.api.requests.post", patch_api.mock_post)
    def test_login_does_not_leak_the_access_token(self):
        with patch.dict(os.environ, {}, clear=True):
            client = iam_sdk.client(
                api_access_key="userapi", api_secret_key=self.PASSWORD
            )
            with self.assertLogs("iam_sdk.api", level="DEBUG") as logs:
                client.login()

        output = "\n".join(logs.output)
        self.assertNotIn(client.token, output)

    @patch("iam_sdk.api.requests.post", patch_api.mock_post)
    def test_unsafe_flag_shows_the_real_value(self):
        with patch.dict(os.environ, {}, clear=True):
            output = self._login(unsafe_debug_logging=True)

        self.assertIn(self.PASSWORD, output)

    @patch("iam_sdk.api.requests.post", patch_api.mock_post)
    def test_unsafe_env_var_shows_the_real_value(self):
        with patch.dict(os.environ, {UNSAFE_DEBUG_LOGGING_ENV: "true"}):
            output = self._login()

        self.assertIn(self.PASSWORD, output)


if __name__ == "__main__":
    unittest.main()
