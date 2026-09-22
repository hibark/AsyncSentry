import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from core.models import Vulnerability
from core.risk_engine import RiskEngine


def generate_html_report(target: str, vulnerabilities: list[Vulnerability], output_path: str = "reports/report.html"):
    risk_data = RiskEngine.calculate_score(vulnerabilities)
    sorted_vulns = RiskEngine.sort_by_severity(vulnerabilities)

    env = Environment(loader=FileSystemLoader("reporting"))
    template = env.get_template("template.html")

    html_content = template.render(
        target=target,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        risk_level=risk_data["risk_level"],
        total_score=risk_data["total_score"],
        total_vulnerabilities=risk_data["total_vulnerabilities"],
        breakdown=risk_data["breakdown"],
        vulnerabilities=[
            {
                "name": v.name,
                "severity": v.severity.value,
                "endpoint": v.endpoint,
                "description": v.description,
                "evidence": v.evidence or "-",
                "remediation": v.remediation or "-"
            }
            for v in sorted_vulns
        ]
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] Rapport HTML généré : {output_path}")
    return output_path
