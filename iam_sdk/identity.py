"""Identity claims of a JWT, for audit logging.

The SDK redacts tokens from the logs, so by default nothing in the logs
tells who performed a request. ``log_caller_identity`` brings that trail
back without exposing the token: only the ``ext`` claims of the JWT
(username, email, tenant, principal, ...) are logged.

The payload is decoded WITHOUT verifying the signature. It is meant for
logging only and must never be used to take an authorization decision -
use :meth:`iam_sdk.api.Client.validate_token` for that.
"""

import base64
import binascii
import json
from typing import Any, Dict

LOG_CALLER_IDENTITY_ENV = "IAM_SDK_LOG_CALLER_IDENTITY"


def decode_jwt_payload(token: Any) -> Dict[str, Any]:
    """Best effort decode of the JWT payload.

    Returns an empty dict when the token is missing or not decodable - this
    runs on the logging path, so it must never raise.
    """
    if not token or not isinstance(token, str):
        return {}

    parts = token.split(".")
    if len(parts) < 2:
        return {}

    payload = parts[1]
    # base64url without the "=" padding, as required by the JWT spec
    payload += "=" * (-len(payload) % 4)

    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, TypeError, binascii.Error, UnicodeDecodeError):
        return {}

    return claims if isinstance(claims, dict) else {}


def token_ext_claims(token: Any) -> Dict[str, Any]:
    """The ``ext`` claims of a JWT: who the token belongs to.

    Example: ``{"username": "userapi", "email": "user@totvs.com.br",
    "tenant": "cseinf", "principal": "trn::tcloud::iam::...", "mfa": "active"}``
    """
    ext = decode_jwt_payload(token).get("ext")

    return ext if isinstance(ext, dict) else {}
