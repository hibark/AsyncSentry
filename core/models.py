from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

class Severity(Enum):
    CRITICAL = "Critique"
    HIGH = "Élevé"
    MEDIUM = "Moyen"
    LOW = "Faible"
    INFO = "Info"

@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    form_data: Dict[str, str] = field(default_factory=dict)

@dataclass
class Vulnerability:
    name: str
    severity: Severity
    endpoint: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None

@dataclass
class ScanResult:
    target: str
    endpoints: List[Endpoint] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)