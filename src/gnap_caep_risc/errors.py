# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Failures reported by this library. Application code treats them the same way and logs the code."""


class ErrorContinuation:
    def __init__(self, uri, access_token, wait=None):
        self.uri = uri
        self.access_token = access_token
        self.wait = wait


class GnapError(Exception):
    """A config, discovery, protocol, validation, signature, or ssf failure."""

    def __init__(self, code, message, cause=None, gnap_error=None, context=None, continuation=None):
        super().__init__(message)
        self.code = code
        self.gnap_error = gnap_error
        self.context = context
        self.continuation = continuation
        if cause is not None:
            self.__cause__ = cause
