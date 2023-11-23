import logging
from .api import Client


def client(
    endpoint_authn=None,
    endpoint_authz=None,
    validate_ssl=True,
    api_access_key=None,
    api_secret_key=None,
):
    return Client(
        endpoint_authn=endpoint_authn,
        endpoint_authz=endpoint_authz,
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
