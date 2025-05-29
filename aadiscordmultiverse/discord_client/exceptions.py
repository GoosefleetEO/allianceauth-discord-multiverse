"""Custom exceptions for the Discord Client package."""

import math


class DiscordClientException(Exception):
    """Base Exception for the Discord client."""


class DiscordApiBackoff(DiscordClientException):
    """Exception signaling we need to backoff from sending requests to the API for now.

    Args:
        retry_after: time to retry after in milliseconds
    """

    def __init__(self, retry_after: int):
        super().__init__()
        self.retry_after = int(retry_after)

    @property
    def retry_after_seconds(self):
        """Time to retry after in seconds."""
        return math.ceil(self.retry_after / 1000)


class DiscordRateLimitExhausted(DiscordApiBackoff):
    """Exception signaling that the total number of requests allowed under the
    current rate limit have been exhausted and weed to wait until next reset.
    """


class DiscordTooManyRequestsError(DiscordApiBackoff):
    """API has responded with a 429 Too Many Requests Error.
    Need to backoff for now.
    """
