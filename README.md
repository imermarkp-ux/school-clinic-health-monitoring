# School Clinic Health Monitoring System

A Flask + SQLite starter application adapted from the supplied Student Analytics Dashboard project and its Flask setup guide.

## Features
- Staff login with administrator and nurse roles
- Student directory and student health profile
- Clinic visit logging
- Vital-sign entry linked to a student and optional visit
- Dashboard statistics and Chart.js visualizations
- Visit history and CSV export
- Administrator-managed staff accounts

## 1. Requirements
- Python 3.10 or newer
- Internet connection for the Chart.js and Google Fonts CDN assets (the Flask app itself runs locally)

## 2. Install and run (Windows PowerShell)
Open PowerShell in this project folder:

```powershell
python --version
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

If PowerShell blocks activation, use Command Prompt instead:

```bat
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser. Stop the server with `CTRL+C`.

## Demo login accounts
- Administrator: `admin` / `Clinic@12345`
- Nurse: `nurse` / `Nurse@12345`

These are development-only credentials. Change them and set a long random `SECRET_KEY` before any deployment. The default secret is not suitable for production.

## Database
The SQLite database (`clinic.db`) is created automatically on first run. It is stored in this project folder. Back it up securely and restrict access to the computer and folder.

## Important privacy and safety notes
This is a learning/demo starter, not a certified electronic medical record or clinical decision-support system. Do not enter real student health information until the school has approved the system and its privacy/security controls. Health information is sensitive personal information. A real deployment needs a privacy impact assessment, appropriate school authorization and notices/consents where required, secure hosting, HTTPS, strong password policy, account lifecycle controls, audit logs, backups, retention/deletion rules, and review by the school's data protection officer and qualified health personnel. Vital-sign entries are stored as measurements only; the system does not diagnose or interpret them.

## Main structure
```
school_clinic_health_monitoring/
├── app.py
├── requirements.txt
├── README.md
├── clinic.db              # created automatically at first run
├── templates/
└── static/
    ├── css/style.css
    └── js/
```
