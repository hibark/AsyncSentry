from core.models import Vulnerability, Severity

# Poids numérique par criticité (pour calculer un score global)
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class RiskEngine:
    @staticmethod
    def calculate_score(vulnerabilities: list[Vulnerability]) -> dict:
        """Calcule un score de risque global et des statistiques par criticité."""
        counts = {sev: 0 for sev in Severity}
        total_score = 0

        for vuln in vulnerabilities:
            counts[vuln.severity] += 1
            total_score += SEVERITY_WEIGHTS.get(vuln.severity, 0)

        # Détermination d'un niveau de risque global
        if counts[Severity.CRITICAL] > 0:
            risk_level = "CRITIQUE"
        elif counts[Severity.HIGH] > 0:
            risk_level = "ÉLEVÉ"
        elif counts[Severity.MEDIUM] > 0:
            risk_level = "MOYEN"
        elif counts[Severity.LOW] > 0:
            risk_level = "FAIBLE"
        else:
            risk_level = "AUCUN"

        return {
            "total_score": total_score,
            "risk_level": risk_level,
            "total_vulnerabilities": len(vulnerabilities),
            "breakdown": {sev.value: count for sev, count in counts.items() if count > 0}
        }

    @staticmethod
    def sort_by_severity(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        """Trie les vulnérabilités de la plus critique à la moins critique."""
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(vulnerabilities, key=lambda v: order.get(v.severity, 99))