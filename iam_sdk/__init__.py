import logging
from .api import Client


def client(
    endpoint_authn=None,
    endpoint_authz=None,
    endpoint_cp=None,
    validate_ssl=True,
    api_access_key=None,
    api_secret_key=None,
    endpoint_authz_fallbacks=None,
    timeout=30,
    unsafe_debug_logging=None,
):
    """
    Build an IAM SDK client.

    :param endpoint_authz_fallbacks: optional list of extra authz endpoints
        (or a comma-separated string) tried in order when the primary
        ``endpoint_authz`` times out or is unreachable. Can also be provided
        via the ``IAM_AUTHZ_FALLBACK_ENDPOINTS`` environment variable.
    :param timeout: per-request timeout (seconds) applied to authz calls.
    :param unsafe_debug_logging: defaults to False, which redacts credentials,
        tokens and authorization headers from the DEBUG logs. Set it to True
        (or export ``IAM_SDK_UNSAFE_DEBUG_LOGGING=true``) to log the real
        values instead - a warning is logged because the secrets then reach
        the logs in plaintext.
    """
    return Client(
        endpoint_authn=endpoint_authn,
        endpoint_authz=endpoint_authz,
        endpoint_cp=endpoint_cp,
        endpoint_authz_fallbacks=endpoint_authz_fallbacks,
        timeout=timeout,
        unsafe_debug_logging=unsafe_debug_logging,
    ).client(
        api_access_key=api_access_key,
        api_secret_key=api_secret_key,
        validate_ssl=validate_ssl,
    )


# Set up logging to ``/dev/null`` like a library is supposed to.
# https://docs.python.org/3.3/howto/logging.html#configuring-logging-for-a-library
class NullHandler(logging.Handler):
    def emit(self, record):
        pass


logging.getLogger("iam_sdk").addHandler(NullHandler())
