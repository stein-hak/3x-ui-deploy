"""
Custom exceptions for 3x-ui API client
"""


class XUIException(Exception):
    """Base exception for all XUI client errors"""
    pass


class AuthenticationError(XUIException):
    """Raised when authentication fails"""
    pass


class APIError(XUIException):
    """Raised when API request fails"""
    def __init__(self, message, status_code=None, response=None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class NotFoundError(APIError):
    """Raised when requested resource is not found"""
    pass
