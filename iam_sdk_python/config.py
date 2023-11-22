import os

DEFAULT_ENDPOINT = "http://localhost:9000/api"


class Config:
    def __init__(self, **kargs) -> None:
        self.endpoint_authn = kargs.get(
            "endpoint", os.getenv("IAM_AUTHN_ENDPOINT", DEFAULT_ENDPOINT)
        )
        self.endpoint_authz = kargs.get(
            "endpoint", os.getenv("IAM_AUTHZ_ENDPOINT", DEFAULT_ENDPOINT)
        )

    def get_endpoint_authn(self):
        return self.endpoint_authn

    def get_endpoint_authz(self):
        return self.endpoint_authz
