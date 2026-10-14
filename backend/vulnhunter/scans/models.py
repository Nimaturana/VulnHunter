from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, HttpUrl


DEFAULT_SCANNERS = [
    "xss",
    "sql_injection",
    "security_headers",
    "ssl_tls",
    "directory_scan",
]


class ScanRequest(BaseModel):
    url: HttpUrl
    scan_types: list[str] = Field(default_factory=lambda: list(DEFAULT_SCANNERS))
    description: Optional[str] = Field(default=None, max_length=500)


class Finding(BaseModel):
    type: str
    severity: str
    location: str
    scanner: str
    description: str = ""
    recommendation: str = ""
    evidence: str = ""
    confidence: str = "low"


class Scan(BaseModel):
    scan_id: str
    url: str
    scan_types: list[str]
    status: str = "pending"
    started_at: datetime
    completed_at: Optional[datetime] = None
    results: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"
    errors: dict[str, str] = Field(default_factory=dict)
    current_scanner: Optional[str] = None
    progress_percentage: int = 0
    task_id: Optional[str] = None
    execution_mode: str = "background"
    queued_at: Optional[datetime] = None
    worker_started_at: Optional[datetime] = None
    report_status: str = "not_generated"


class ScanSummary(BaseModel):
    scan_id: str
    url: str
    status: str
    total_vulnerabilities: int
    risk_level: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    progress_percentage: int = 0
    current_scanner: Optional[str] = None
    task_id: Optional[str] = None
    execution_mode: str = "background"
    queued_at: Optional[datetime] = None
    report_status: str = "not_generated"


class ReportInfo(BaseModel):
    scan_id: str
    status: str
    file_name: Optional[str] = None
    size_bytes: Optional[int] = None
    sha256: Optional[str] = None
    generated_at: Optional[datetime] = None
    download_count: int = 0
    last_downloaded_at: Optional[datetime] = None
