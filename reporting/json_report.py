import json
from datetime import datetime
from dataclasses import asdict
from core.models import Vulnerability
from core.risk_engine import RiskEngine


def generate_json_report(target: str, vulnerabilities: list[Vulnerability], output_path: str = "reports/report.json"):
    risk_data = RiskEngine.calculate_score(vulnerabilities)
    sorted_vulns = RiskEngine.sort_by_severity(vulnerabilities)

    report = {
        "scan_info": {
            "target": target,
            "date": datetime.now().isoformat(),
            "tool": "PurpleScan"
        },
        "risk_summary": risk_data,
        "vulnerabilities": [
            {
                "name": v.name,
                "severity": v.severity.value,
                "endpoint": v.endpoint,
                "description": v.description,
                "evidence": v.evidence,
                "remediation": v.remediation
            }
            for v in sorted_vulns
        ]
    }

    import os
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"[+] Rapport JSON généré : {output_path}")
    return output_path