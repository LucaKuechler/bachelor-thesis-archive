from typing import Any

class SIGMARulePathMissingError(Exception):
    def __init__(self, message: Any):            
        super().__init__(message)
