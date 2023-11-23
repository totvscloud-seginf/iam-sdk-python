class TokenInvalidError(BaseException):
    """
    Token expired or invalid
    """

    def __init__(
        self,
    ) -> None:
        msg = "Current token is not valid or is expired"
        super().__init__(self, msg)


class NotAuthorizedException(BaseException):
    """
    Raised when trying to make a request and do not have the required
    permissions
    """

    def __init__(
        self,
        message,
    ) -> None:
        msg = (
            "You do not have permission to make this request\n",
            f"API Response: {message}",
        )
        super().__init__(self, msg)


class InvalidRequestError(BaseException):
    """
    Raised when the api request, contains invalid payload
    """

    def __init__(
        self,
        status_code: int = 500,
        message: str = "",
    ) -> None:
        msg = (
            f"Invalid API Request, received http {status_code}\n"
            f"API Response: {message}"
        )
        super().__init__(self, msg)
