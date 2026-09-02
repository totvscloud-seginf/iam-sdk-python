"""Keep credentials and tokens out of the SDK debug logs.

Every request/response the SDK writes at DEBUG level goes through a
:class:`Redactor`. By default the values of sensitive keys (passwords,
access tokens, ``Authorization`` headers, ...) are replaced by
``***REDACTED***`` before reaching the log record.

The redaction can be turned off with ``unsafe_debug_logging`` when the raw
values are really needed while debugging. Doing so logs a warning to make it
obvious that secrets are being written to the logs in plaintext.
"""

import json
import logging
import re
from collections.abc import Mapping
from typing import Any

logger = logging.getLogger(__name__)

REDACTED = "***REDACTED***"

UNSAFE_DEBUG_LOGGING_ENV = "IAM_SDK_UNSAFE_DEBUG_LOGGING"

# Keys whose value is a credential / token. The comparison normalizes the key
# to lowercase without "-" and "_", so "x-token-jwt", "X_Token_JWT" and
# "xtokenjwt" are all treated as the same key.
SENSITIVE_KEYS = frozenset(
    [
        "apikey",
        "apisecretkey",
        "accesskey",
        "accesssecretkey",
        "accesstoken",
        "authorization",
        "clientsecret",
        "cookie",
        "credentials",
        "idtoken",
        "jwt",
        "password",
        "passwd",
        "refreshtoken",
        "secret",
        "secretaccesskey",
        "secretkey",
        "setcookie",
        "token",
        "tokenjwt",
        "xtokenjwt",
    ]
)

# A JWT anywhere inside a free-form string (non JSON bodies, "Bearer ..."
# header values, error messages, ...).
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
_BEARER_RE = re.compile(r"\b(bearer)\s+\S+", re.IGNORECASE)


def _normalize_key(key: Any) -> str:
    return str(key).replace("-", "").replace("_", "").lower()


def _is_sensitive(key: Any) -> bool:
    return _normalize_key(key) in SENSITIVE_KEYS


def redact_str(value: str) -> str:
    """Scrub tokens found inside a free-form string."""
    value = _BEARER_RE.sub(r"\1 " + REDACTED, value)
    return _JWT_RE.sub(REDACTED, value)


def redact_data(value: Any) -> Any:
    """Recursively replace the values of sensitive keys of a payload/mapping.

    Works for dicts (including ``requests`` case insensitive headers), lists
    and plain strings. Non sensitive strings are still scrubbed for tokens.
    """
    if isinstance(value, Mapping):
        return {
            key: REDACTED if _is_sensitive(key) else redact_data(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [redact_data(item) for item in value]

    if isinstance(value, str):
        return redact_str(value)

    return value


def redact_text(text: Any) -> Any:
    """Redact a raw response body.

    JSON bodies are parsed so only the sensitive keys are replaced and the
    rest stays readable. Anything else is scrubbed for tokens.
    """
    if not isinstance(text, str) or not text:
        return text

    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return redact_str(text)

    try:
        return json.dumps(redact_data(parsed))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return redact_str(text)


class _LazyRedacted:
    """Defer the redaction until the log record is actually formatted.

    Keeps ``logger.debug("%s", redactor.data(payload))`` free when the DEBUG
    level is disabled, the same way the stdlib lazy formatting does.
    """

    __slots__ = ("_value", "_redact")

    def __init__(self, value: Any, redact) -> None:
        self._value = value
        self._redact = redact

    def __str__(self) -> str:
        return str(self._redact(self._value))

    def __repr__(self) -> str:
        return self.__str__()


class Redactor:
    """Wraps values logged by the SDK so credentials never reach the logs.

    :param unsafe: when True the values are logged as-is (plaintext secrets).
    """

    def __init__(self, unsafe: bool = False) -> None:
        self._unsafe = bool(unsafe)

        if self._unsafe:
            logger.warning(
                "%s is ENABLED: credentials, tokens and authorization headers "
                "will be written to the debug logs in PLAINTEXT. "
                "Never enable it in production.",
                UNSAFE_DEBUG_LOGGING_ENV,
            )

    @property
    def unsafe(self) -> bool:
        return self._unsafe

    def data(self, value: Any) -> Any:
        """Wrap a payload / headers mapping for ``%s`` logging."""
        if self._unsafe:
            return value

        return _LazyRedacted(value, redact_data)

    def text(self, value: Any) -> Any:
        """Wrap a raw request/response body for ``%s`` logging."""
        if self._unsafe:
            return value

        return _LazyRedacted(value, redact_text)
