"""JWT misconfiguration scanner.

This scanner checks for common JWT security issues:
- Algorithm confusion (alg:none attack)
- Missing expiration claim
- Expired tokens
- Weak/common secrets via brute-force
"""

import time
from pathlib import Path

import jwt
from sentri import config
from sentri.models import Finding, ScanResult, Severity
from sentri.scanners.base import BaseScanner
from sentri.utils import jwt as jwt_utils


class JWTScanner(BaseScanner):
    """
    Scanner for JWT token security issues.
    
    Checks for:
    - alg:none vulnerability
    - Missing exp claim
    - Expired tokens
    - Weak secrets via brute-force
    """
    
    def __init__(self, target: str, options: dict | None = None):
        """Initialize the JWT scanner."""
        super().__init__(target, options)
        self.wordlist_path = config.get_wordlist_path(
            options.get("wordlist") if options else None
        )
    
    def scan(self) -> ScanResult:
        """
        Run JWT security checks.
        
        Returns:
            ScanResult with all JWT security findings
        """
        token = self.target.strip()
        
        if not token or token.count(".") < 2:
            self.findings.append(
                self._create_finding(
                    title="Invalid JWT Format",
                    description="The provided token does not appear to be a valid JWT (must have 3 parts separated by dots).",
                    severity=Severity.INFO,
                    recommendation="Ensure you're passing a valid JWT token in the format header.payload.signature",
                )
            )
            return self._build_result()
        
        # Check for algorithm confusion vulnerability
        self._check_algorithm_confusion(token)
        
        # Check for missing expiration
        self._check_expiration(token)
        
        # Check if token is expired
        self._check_expired(token)
        
        # Brute-force weak secrets for HMAC-signed tokens
        if jwt_utils.is_hmac_signed(token):
            self._check_weak_secret(token)
        
        return self._build_result()
    
    def _check_algorithm_confusion(self, token: str) -> None:
        """
        Check for algorithm confusion vulnerability (alg:none).
        
        Why this matters:
        The 'alg:none' attack exploits the JWT header's 'alg' field.
        If a server accepts tokens with alg=none and doesn't verify signatures,
        an attacker can forge tokens by setting alg to 'none' and omitting
        the signature entirely. This is a critical vulnerability.
        """
        alg = jwt_utils.extract_alg(token)
        
        if alg and alg.lower() == "none":
            self.findings.append(
                self._create_finding(
                    title="Algorithm Confusion (alg:none)",
                    description=f"The token uses algorithm '{alg}', which disables signature verification. "
                                "An attacker can bypass authentication by crafting tokens with alg=none.",
                    severity=Severity.CRITICAL,
                    recommendation="Configure the JWT library to reject tokens with alg=none. "
                                  "Explicitly whitelist allowed algorithms (e.g., RS256, ES256).",
                )
            )
    
    def _check_expiration(self, token: str) -> None:
        """
        Check for missing exp (expiration) claim.
        
        Why this matters:
        Without an exp claim, tokens never expire. If a token is compromised,
        it remains valid indefinitely, giving attackers permanent access.
        Always require expiration for time-limited access.
        """
        exp = jwt_utils.extract_exp(token)
        
        if exp is None:
            self.findings.append(
                self._create_finding(
                    title="Missing Expiration Claim",
                    description="The token has no 'exp' claim, meaning it never expires. "
                                "If this token is compromised, attackers have permanent access.",
                    severity=Severity.MEDIUM,
                    recommendation="Always include an 'exp' claim in JWTs and verify it on the server. "
                                  "Set reasonable expiration times (e.g., 15-60 minutes for access tokens).",
                )
            )
    
    def _check_expired(self, token: str) -> None:
        """
        Check if the token is expired.
        
        Why this matters:
        An expired token should be rejected. While this is typically
        handled properly by JWT libraries, manual checks may miss it.
        """
        exp = jwt_utils.extract_exp(token)
        
        if exp and exp < time.time():
            self.findings.append(
                self._create_finding(
                    title="Expired Token",
                    description=f"The token expired at {exp} (Unix timestamp). "
                                "This token is no longer valid and should be rejected.",
                    severity=Severity.INFO,
                    recommendation="Request a new token from the authentication service.",
                )
            )
    
    def _check_weak_secret(self, token: str) -> None:
        """
        Attempt to brute-force the JWT secret using a wordlist.
        
        Why this matters:
        Many developers use weak, predictable secrets (e.g., 'secret', 'password', '123456').
        If a secret can be cracked, attackers can forge valid tokens for any user.
        This is a critical vulnerability if successful.
        """
        # Get wordlist
        wordlist = self._load_wordlist()
        if not wordlist:
            return
        
        # Get the signing algorithm
        alg = jwt_utils.extract_alg(token)
        if not alg:
            return
        
        # Try each secret
        for secret in wordlist:
            secret = secret.strip()
            if not secret:
                continue
            
            try:
                jwt.decode(
                    token,
                    secret,
                    algorithms=[alg],
                    options={
                        "verify_signature": True,
                        "verify_exp": False,  # Don't fail on expired tokens
                        "verify_aud": False,
                        "verify_iss": False,
                    },
                )
                # If we get here, the secret was correct
                self.findings.append(
                    self._create_finding(
                        title="Weak JWT Secret Cracked",
                        description=f"The token's secret was successfully cracked: '{secret}'. "
                                    "An attacker can now forge tokens for any user.",
                        severity=Severity.CRITICAL,
                        recommendation="Change the JWT signing secret to a strong, random value. "
                                      "Use a minimum of 256 bits of entropy. "
                                      "Consider using asymmetric keys (RS256) instead of HMAC.",
                    )
                )
                return  # Only report the first successful crack
            except jwt.InvalidSignatureError:
                continue  # Try next secret
            except jwt.InvalidTokenError:
                continue  # Try next secret
    
    def _load_wordlist(self) -> list[str]:
        """Load the secrets wordlist."""
        if not self.wordlist_path.exists():
            return []
        
        with open(self.wordlist_path, "r", encoding="utf-8") as f:
            return f.readlines()
    
    def _build_result(self) -> ScanResult:
        """Build the scan result."""
        return ScanResult(
            scanner_name="jwt",
            target=self.target[:50] + "..." if len(self.target) > 50 else self.target,
            findings=self.findings,
            passed=self._passed(),
            summary=self._summary_text(),
        )