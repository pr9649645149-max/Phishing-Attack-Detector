# Phishing Attack Detector

A simple Python project that detects phishing attempts using URL heuristic scoring and email content analysis.

## Features
- Analyze a URL and assign a phishing risk score
- Detect suspicious email content
- Expose a FastAPI endpoint for detection

## Setup
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt