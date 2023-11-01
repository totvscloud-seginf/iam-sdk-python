import os

DEFAULT_ENDPOINT = "http://localhost:9000/api"


class Config:
    def __init__(self, **kargs) -> None:
        self.endpoint = kargs.get(
            "endpoint", os.getenv("IAM_AUTHN_ENDPOINT", DEFAULT_ENDPOINT)
        )

    def get_endpoint(self):
        return self.endpoint
