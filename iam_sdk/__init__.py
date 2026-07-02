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
):
    """
    Build an IAM SDK client.

    :param endpoint_authz_fallbacks: optional list of extra authz endpoints
        (or a comma-separated string) tried in order when the primary
        ``endpoint_authz`` times out or is unreachable. Can also be provided
        via the ``IAM_AUTHZ_FALLBACK_ENDPOINTS`` environment variable.
    :param timeout: per-request timeout (seconds) applied to authz calls.
    """
    return Client(
        endpoint_authn=endpoint_authn,
        endpoint_authz=endpoint_authz,
        endpoint_cp=endpoint_cp,
        endpoint_authz_fallbacks=endpoint_authz_fallbacks,
        timeout=timeout,
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
