"""
3x-ui API Client Library

A Python client for interacting with the 3x-ui panel API.
"""

from .client import XUIClient
from .exceptions import (
    XUIException,
    AuthenticationError,
    APIError,
    NotFoundError
)

__version__ = "0.1.0"
__all__ = [
    "XUIClient",
    "XUIException",
    "AuthenticationError",
    "APIError",
    "NotFoundError"
]
