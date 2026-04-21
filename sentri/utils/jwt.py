"""JWT parsing and decoding utilities."""

import base64
import json
from typing import Any


def decode_jwt_part(part: str) -> dict[str, Any]:
    """
    Decode a base64url-encoded JWT part (header or payload).
    
    Args:
        part: Base64url-encoded string (header, payload, or signature)
    
    Returns:
        Decoded JSON as a dictionary
    """
    # Add padding if necessary
    padding = 4 - len(part) % 4
    if padding != 4:
        part += "=" * padding
    
    decoded = base64.urlsafe_b64decode(part)
    return json.loads(decoded)


def parse_jwt_header(token: str) -> dict[str, Any]:
    """
    Parse and decode the header of a JWT token.
    
    Args:
        token: A JWT string
    
    Returns:
        Decoded header as a dictionary
    """
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format: too few parts")
    
    return decode_jwt_part(parts[0])


def parse_jwt_payload(token: str) -> dict[str, Any]:
    """
    Parse and decode the payload of a JWT token.
    
    Args:
        token: A JWT string
    
    Returns:
        Decoded payload as a dictionary
    """
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format: too few parts")
    
    return decode_jwt_part(parts[1])


def extract_alg(token: str) -> str | None:
    """Extract the algorithm claim from a JWT token."""
    try:
        header = parse_jwt_header(token)
        return header.get("alg")
    except Exception:
        return None


def extract_exp(token: str) -> int | None:
    """Extract the expiration time claim from a JWT token."""
    try:
        payload = parse_jwt_payload(token)
        return payload.get("exp")
    except Exception:
        return None


def extract_kid(token: str) -> str | None:
    """Extract the key ID claim from a JWT token."""
    try:
        header = parse_jwt_header(token)
        return header.get("kid")
    except Exception:
        return None


def get_signature(token: str) -> str | None:
    """Extract the signature part from a JWT token."""
    parts = token.split(".")
    if len(parts) >= 3:
        return parts[2]
    return None


def is_hmac_signed(token: str) -> bool:
    """Check if the token uses an HMAC algorithm (HS256, HS384, HS512)."""
    from sentri import config
    
    alg = extract_alg(token)
    return alg in config.JWT_HMAC_ALGORITHMS