"""Data models for scan results and findings."""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """
    Severity levels for security findings.
    
    Uses IntEnum to allow comparison operations (CRITICAL > HIGH > MEDIUM > LOW > INFO).
    """
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    """
    Represents a single security issue discovered during scanning.
    
    Attributes:
        title: Short description of the finding
        description: Detailed explanation of the vulnerability
        severity: How critical this finding is
        recommendation: Suggested fix or mitigation
    """
    title: str
    description: str
    severity: Severity
    recommendation: str


@dataclass
class ScanResult:
    """
    Results from a single scanner run.
    
    Attributes:
        scanner_name: Identifier for which scanner produced this result
        target: What was scanned (URL, token, file path, etc.)
        findings: List of security issues found
        passed: Whether the scan passed (no critical/high findings)
        summary: Human-readable summary of results
    """
    scanner_name: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    passed: bool = True
    summary: str = ""

    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Count findings by severity level."""
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def max_severity(self) -> Severity:
        """Get the highest severity among all findings."""
        if not self.findings:
            return Severity.INFO
        return max(self.findings, key=lambda f: f.severity).severity