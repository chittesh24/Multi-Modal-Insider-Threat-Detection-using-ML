
# Insider Threat Dashboard — Updated UI (app_new.py)

This package contains an updated, eye-catching Streamlit UI (app_new.py) that highlights threat users separately and provides a clean dashboard for demos.

Files:
- app_new.py : Polished Streamlit dashboard (open with `streamlit run app_new.py`)
- requirements.txt : Python dependencies
- README.md : This file

Usage:
1. Place your dataset in one of the expected locations, or upload it using the sidebar file uploader in the app.
   Expected paths (app will try these automatically):
   - insider_10pct_threats/insider_10pct_threats.csv
   - insider_illegal_demo/insider_illegal_demo.csv
   - insider_dataset.csv
   - insider_project/insider_dataset.csv

2. Create and activate a venv, install requirements, and run:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   streamlit run app_new.py
   ```

Notes:
- This app is for demo/educational purposes and uses synthetic data. Do not use it as sole evidence for real investigations.
