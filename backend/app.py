from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import json
import os

app = FastAPI(title="PipeGuard")

BASE_DIR = os.path.dirname(__file__)
REPORTS_DIR = os.path.join(BASE_DIR, "..", "reports")
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")

# Serve dashboard static files
app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")


# -----------------------------
# Root Dashboard
# -----------------------------
@app.get("/")
def root():
    return FileResponse(os.path.join(DASHBOARD_DIR, "index.html"))


# -----------------------------
# Pipeline Status API
# -----------------------------
@app.get("/api/status")
def status():

    secrets = 0
    sast = 0
    cve = 0
    iac = 0
    risk_score = 0

    try:
        with open("../reports/secrets.json") as f:
            secrets = len(json.load(f))
    except:
        pass

    try:
        with open("../reports/sast.json") as f:
            sast = len(json.load(f)["results"])
    except:
        pass

    try:
        with open("../reports/trivy.txt") as f:
            data = f.read()
            if "CRITICAL" in data:
                cve = 1
    except:
        pass

    try:
        with open("../reports/iac.txt") as f:
            data = f.read()
            if "HIGH" in data:
                iac = 1
    except:
        pass

    # Read risk score from summary.json
    try:
        with open("../reports/summary.json") as f:
            summary = json.load(f)
            risk_score = summary.get("risk_score", 0)
    except:
        pass

    return {
        "secrets": secrets,
        "sast": sast,
        "cve": cve,
        "iac": iac,
        "risk_score": risk_score
    }


# -----------------------------
# Scan History API
# -----------------------------
@app.get("/api/history")
def history():

    history_file = os.path.join(REPORTS_DIR, "history.json")

    if os.path.exists(history_file):
        with open(history_file) as f:
            return json.load(f)

    return []
