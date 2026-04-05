from typing import Optional, List, Dict
from pydantic import BaseModel, Field

class DetectionResult(BaseModel):
    is_wordpress: bool
    version: Optional[str] = None
    exposed_endpoints: List[str] = Field(default_factory=list)
    theme: Optional[str] = None
    plugins: List[str] = Field(default_factory=list)
    interesting_files: List[Dict[str, str]] = Field(default_factory=list)
    server_info: str = "Unknown"
    confidence: str = "None"

class ExploitResult(BaseModel):
    vulnerable: bool
    vulnerability_type: str
    severity: str  # Critical, High, Medium, Low, Info
    confidence: str  # Confirmed, Probable, Possible
    proof_of_concept: str
    extracted_data: Optional[str] = None
    remediation: str
    cvss_score: float

class FullReport(BaseModel):
    target: str
    scan_duration: str
    wordpress_version: Optional[str]
    findings: List[ExploitResult]
    summary: str
    risk_level: str
