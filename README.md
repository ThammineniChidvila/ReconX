# ReconX — Unified Cybersecurity Reconnaissance Platform

ReconX is a Python-based cybersecurity reconnaissance platform designed to bring essential domain intelligence and security assessment capabilities together in one dashboard.

It helps users collect and organize publicly available domain information, inspect DNS records, review SSL/TLS certificates, discover subdomains, identify web technologies, and maintain scan history.

## Features

- **Domain Intelligence:** Gather publicly available information about a target domain.
- **DNS Analysis:** Inspect DNS records and related information.
- **Subdomain Discovery:** Identify publicly discoverable subdomains.
- **SSL/TLS Analysis:** Review certificate information.
- **Technology Detection:** Identify technologies used by websites.
- **Port Assessment:** Perform limited port assessment with domain ownership verification.
- **Scan History:** Store and review previous scan results.
- **PDF Reports:** Generate reports for completed assessments.
- **Dashboard:** Access available tools through a unified web interface.

## Technology Stack

- Python
- Flask
- SQLite
- HTML
- CSS
- JavaScript

## Project Structure

```text
ReconX/
├── app.py
├── config.py
├── requirements.txt
├── .env.example
├── README.md
├── database/
│   ├── __init__.py
│   ├── db.py
│   └── models.py
├── modules/
├── reports/
├── static/
├── templates/
└── tests/
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/ThammineniChidvila/ReconX.git
cd ReconX
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the environment

**Windows PowerShell:**

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the application

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

## Testing

Run the automated test suite using:

```bash
python -m unittest discover -s tests -t . -v
```

## Security and Ethical Use

ReconX is intended for educational purposes, authorized security testing, and legitimate defensive security research.

- Only assess domains and systems you own or have explicit permission to test.
- Public intelligence collection does not imply authorization for active testing.
- Active port assessment is restricted by domain ownership verification.
- Do not use this project for unauthorized scanning or disruptive activities.

## Project Status

Developed as a cybersecurity learning and portfolio project. Features and capabilities may evolve as development continues.

## Author

**Thammineni Chidvila**

GitHub: [@ThammineniChidvila](https://github.com/ThammineniChidvila)

**Repository:** [ReconX](https://github.com/ThammineniChidvila/ReconX)

---

*Built to explore cybersecurity reconnaissance, domain intelligence, and defensive security assessment.*
