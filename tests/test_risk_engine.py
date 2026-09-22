from core.models import Vulnerability, Severity
from core.risk_engine import RiskEngine

def make_vuln(severity):
    return Vulnerability(name="Test", severity=severity, endpoint="http://test", description="desc")

def test_calculate_score_empty():
    result = RiskEngine.calculate_score([])
    assert result["risk_level"] == "AUCUN"
    assert result["total_vulnerabilities"] == 0

def test_calculate_score_critical():
    vulns = [make_vuln(Severity.CRITICAL), make_vuln(Severity.LOW)]
    result = RiskEngine.calculate_score(vulns)
    assert result["risk_level"] == "CRITIQUE"
    assert result["total_vulnerabilities"] == 2

def test_sort_by_severity():
    vulns = [make_vuln(Severity.LOW), make_vuln(Severity.CRITICAL), make_vuln(Severity.MEDIUM)]
    sorted_vulns = RiskEngine.sort_by_severity(vulns)
    assert sorted_vulns[0].severity == Severity.CRITICAL
    assert sorted_vulns[-1].severity == Severity.LOW