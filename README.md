# SOC Project 2 — Phishing Threat Intelligence Analyzer (UPGRADED v4)

This is the new project folder. It is not the old static version.

## Architecture
Email/alert text -> local IOC extraction -> explainable risk scoring -> optional VirusTotal reputation -> SOC conclusion.

## Features
- URL, IP, email and hash extraction
- risky attachment-name detection
- transparent phishing heuristic scoring
- visual SOC dashboard
- optional VirusTotal URL/IP/hash reputation
- no file uploads to VirusTotal
- API key stored only in `.env`
- evidence and investigation-report folders
- basic automated test

## Windows setup
Open CMD inside this project folder:

python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
copy .env.example .env
python app.py

Then open http://127.0.0.1:5000

127.0.0.1 means the same computer. Port 5000 is where the Flask development server listens.

## VirusTotal
The code contains NO real API key.
Create `.env` from `.env.example` and put your own key there:
VIRUSTOTAL_API_KEY=YOUR_KEY

Never upload `.env` to GitHub.

## Recruiter explanation
“I built a SOC-oriented phishing triage application. It extracts IOCs from email/alert text, applies explainable local risk scoring, and optionally enriches those indicators with VirusTotal reputation. The application mirrors a SOC workflow: detect, validate, investigate, escalate and document.”

## Evidence
Add the supplied VirusTotal screenshots and a screenshot of the new dashboard to `evidence/`.
