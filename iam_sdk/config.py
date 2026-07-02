import os
from typing import List

AUTHN_ENDPOINT = "http://localhost:9000/api"
AUTHZ_ENDPOINT = "http://localhost:8180/v1"
CP_ENDPOINT = "http://localhost:443/v1"


def _parse_endpoint_list(value) -> List[str]:
    """Normalize a list/comma-separated string of endpoints into a clean list.

    Accepts either a real list (as passed by the SDK user) or a
    comma-separated string (as it comes from an environment variable). Empty
    and duplicated values are dropped while preserving order.
    """
    if not value:
        return []

    if isinstance(value, str):
        items = value.split(",")
    else:
        items = list(value)

    endpoints: List[str] = []
    for item in items:
        endpoint = str(item).strip()
        if endpoint and endpoint not in endpoints:
            endpoints.append(endpoint)
    return endpoints


class Config:
    def __init__(self, **kargs) -> None:
        self.endpoint_cp = kargs.get(
            "endpoint_cp", os.getenv("IAM_CP_ENDPOINT", CP_ENDPOINT)
        )
        self.endpoint_authn = kargs.get(
            "endpoint_authn", os.getenv("IAM_AUTHN_ENDPOINT", AUTHN_ENDPOINT)
        )
        # None (the factory default) means "not provided", so fall back to the
        # environment variable / built-in default instead of a literal None.
        endpoint_authz = kargs.get("endpoint_authz")
        self.endpoint_authz = endpoint_authz or os.getenv(
            "IAM_AUTHZ_ENDPOINT", AUTHZ_ENDPOINT
        )
        # Extra authz endpoints supplied by the SDK user, tried as fallbacks
        # (in order) when the primary endpoint times out or is unreachable.
        # None (the factory default) means "not provided", so we fall back to
        # the environment variable.
        fallbacks = kargs.get("endpoint_authz_fallbacks")
        if fallbacks is None:
            fallbacks = os.getenv("IAM_AUTHZ_FALLBACK_ENDPOINTS", "")
        self.endpoint_authz_fallbacks = _parse_endpoint_list(fallbacks)

    def get_endpoint_cp(self):
        return self.endpoint_cp

    def get_endpoint_authn(self):
        return self.endpoint_authn

    def get_endpoint_authz(self):
        return self.endpoint_authz

    def get_endpoint_authz_fallbacks(self) -> List[str]:
        return self.endpoint_authz_fallbacks

    def get_authz_endpoints(self) -> List[str]:
        """Ordered authz endpoints to try: primary first, then fallbacks.

        Duplicates are removed so the same endpoint is never retried twice.
        """
        endpoints = [self.endpoint_authz, *self.endpoint_authz_fallbacks]
        ordered: List[str] = []
        for endpoint in endpoints:
            if endpoint and endpoint not in ordered:
                ordered.append(endpoint)
        return ordered
