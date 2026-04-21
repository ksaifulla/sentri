"""Base scanner class for all security scanners."""

from abc import ABC, abstractmethod
from typing import Any

from sentri.models import Finding, ScanResult, Severity


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners.
    
    All scanners must implement the scan() method to return a ScanResult.
    This ensures a consistent interface across all security checks.
    """
    
    def __init__(self, target: str, options: dict[str, Any] | None = None):
        """
        Initialize the scanner.
        
        Args:
            target: The target to scan (URL, token, file path, etc.)
            options: Optional configuration dictionary for the scanner
        """
        self.target = target
        self.options = options or {}
        self.findings: list[Finding] = []
    
    @abstractmethod
    def scan(self) -> ScanResult:
        """
        Run the security scan.
        
        Returns:
            A ScanResult containing all findings
        """
        pass
    
    def _create_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        recommendation: str,
    ) -> Finding:
        """
        Create a Finding with consistent formatting.
        
        This helper ensures all findings follow the same structure
        and helps maintain consistent severity assignment.
        """
        return Finding(
            title=title,
            description=description,
            severity=severity,
            recommendation=recommendation,
        )
    
    def _passed(self) -> bool:
        """
        Determine if the scan passed (no critical or high findings).
        
        A scan passes if it has no CRITICAL or HIGH severity findings.
        """
        for finding in self.findings:
            if finding.severity >= Severity.HIGH:
                return False
        return True
    
    def _summary_text(self) -> str:
        """Generate summary text from findings."""
        if not self.findings:
            return "No issues found."
        
        counts = self._severity_counts()
        parts = []
        if counts.get(Severity.CRITICAL, 0) > 0:
            parts.append(f"{counts[Severity.CRITICAL]} critical")
        if counts.get(Severity.HIGH, 0) > 0:
            parts.append(f"{counts[Severity.HIGH]} high")
        if counts.get(Severity.MEDIUM, 0) > 0:
            parts.append(f"{counts[Severity.MEDIUM]} medium")
        if counts.get(Severity.LOW, 0) > 0:
            parts.append(f"{counts[Severity.LOW]} low")
        
        return ", ".join(parts) if parts else "Issues found"
    
    def _severity_counts(self) -> dict[Severity, int]:
        """Count findings by severity."""
        counts = {s: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts