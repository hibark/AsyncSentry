# 🛡️ PurpleScan — Scanner de Vulnérabilités Web Asynchrone

Outil VAPT (Vulnerability Assessment and Penetration Testing) développé en Python, adoptant une approche **Purple Team** pour la cartographie et la détection de vulnérabilités web.

## ⚠️ Avertissement légal

**Cet outil ne doit être utilisé QUE sur des applications web pour lesquelles vous avez une autorisation explicite et écrite.**
Le scan actif (SQLi, XSS, LFI) implique l'envoi de payloads malveillants qui peuvent :
- Être détectés comme une attaque réelle par les systèmes de sécurité
- Causer des dommages sur des applications non préparées à ces tests
- Constituer une infraction pénale si réalisé sans autorisation (loi applicable selon votre juridiction)

L'auteur décline toute responsabilité en cas d'usage non autorisé de cet outil.

## Fonctionnalités

- Cartographie asynchrone (crawling) : endpoints, formulaires, paramètres
- Analyse passive : Security Headers, cookies, CORS
- Analyse active : détection SQLi, XSS, Path Traversal/LFI
- Scoring de risque et rapports JSON/HTML

## Installation

\`\`\`bash
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate sous Windows
pip install -r requirements.txt
\`\`\`

## Utilisation

\`\`\`bash
python main.py --target http://localhost:8080 --mode full --cookie "PHPSESSID=xxx;security=low"
\`\`\`

### Options disponibles

| Option | Description | Défaut |
|---|---|---|
| `--target, -t` | URL cible (obligatoire) | - |
| `--depth, -d` | Profondeur de crawl | 2 |
| `--concurrency, -c` | Requêtes simultanées | 5 |
| `--mode, -m` | `passive`, `active` ou `full` | full |
| `--cookie` | Cookies d'authentification | vide |
| `--output-html` | Chemin du rapport HTML | reports/report.html |
| `--output-json` | Chemin du rapport JSON | reports/report.json |

## Environnement de test

Ce projet a été développé et testé sur [DVWA](https://github.com/digininja/DVWA) :

\`\`\`bash
docker run -d --name dvwa-target -p 8080:80 vulnerables/web-dvwa
\`\`\`

## Tests

\`\`\`bash
pytest tests/ -v
\`\`\`

## Architecture

\`\`\`
core/           # Crawler, modèles de données, moteur de scoring
modules/        # Modules passifs et actifs de détection
payloads/       # Charges utiles de test (YAML)
reporting/      # Générateurs de rapports JSON/HTML
tests/          # Tests unitaires
\`\`\`

## Licence

Projet académique / démonstration technique — usage éducatif uniquement.