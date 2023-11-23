class ContextCallerForward:
    """
    ContextCallerForward is the implementation of the required parameters
    to forward to AuthZ.

    These paramters are from the caller (user requesting the action)

    :param caller_token_jwt:
    :param caller_source_ip:
    :param caller_user_agent:
    :param caller_referer:
    :param caller_resource_tenant:
    """

    def __init__(
        self,
        caller_token_jwt="",
        caller_source_ip="",
        caller_user_agent="",
        caller_referer="",
        caller_resource_tenant="",
    ) -> None:
        self._caller_token_jwt = caller_token_jwt
        self._caller_source_ip = caller_source_ip
        self._caller_user_agent = caller_user_agent
        self._caller_referer = caller_referer
        self._caller_resource_tenant = caller_resource_tenant

    @property
    def caller_token_jwt(self):
        return self._caller_token_jwt

    @property
    def caller_source_ip(self):
        return self._caller_source_ip

    @property
    def caller_user_agent(self):
        return self._caller_user_agent

    @property
    def caller_referer(self):
        return self._caller_referer

    @property
    def caller_resource_tenant(self):
        return self._caller_resource_tenant

    def set_caller_token_jwt(self, value: str):
        self._caller_token_jwt = value
        return self

    def set_caller_source_ip(self, value: str):
        self._caller_source_ip = value
        return self

    def set_caller_user_agent(self, value: str):
        self._caller_user_agent = value
        return self

    def set_caller_referer(self, value: str):
        self._caller_referer = value
        return self

    def set_caller_resource_tenant(self, value: str):
        self._caller_resource_tenant = value
        return self

    def mount_header(self) -> dict:
        """
        Get the required parameters and return the expected headers
        to forward for AuthZ
        """
        return {
            "x-token-jwt": self._caller_token_jwt,
            "x-source-ip": self._caller_source_ip,
            "x-user-agent": self._caller_user_agent,
            "x-referer": self._caller_referer,
            "x-resource-tenant": self._caller_resource_tenant,
        }

    def validate(self):
        """
        Check if all required parameters are set
        """
        if self._caller_token_jwt == "":
            raise ValueError('parameter "caller_token_jwt" is required can\'t be empty')

        if self._caller_source_ip == "":
            raise ValueError('parameter "caller_source_ip" is required can\'t be empty')

        if self._caller_user_agent == "":
            raise ValueError(
                'parameter "caller_user_agent" is required can\'t be empty'
            )

        if self._caller_referer == "":
            raise ValueError('parameter "caller_referer" is required can\'t be empty')

        if self._caller_resource_tenant == "":
            raise ValueError(
                'parameter "caller_resource_tenant" is required can\'t be empty'
            )
