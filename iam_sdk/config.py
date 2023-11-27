import os

AUTHN_ENDPOINT = "http://localhost:9000/api"
AUTHZ_ENDPOINT = "http://localhost:8180/v1"


class Config:
    def __init__(self, **kargs) -> None:
        self.endpoint_authn = kargs.get(
            "endpoint_authn", os.getenv("IAM_AUTHN_ENDPOINT", AUTHN_ENDPOINT)
        )
        self.endpoint_authz = kargs.get(
            "endpoint_authz", os.getenv("IAM_AUTHZ_ENDPOINT", AUTHZ_ENDPOINT)
        )

    def get_endpoint_authn(self):
        return self.endpoint_authn

    def get_endpoint_authz(self):
        return self.endpoint_authz
