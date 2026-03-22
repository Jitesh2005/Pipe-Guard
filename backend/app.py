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

    summary_path = os.path.join(REPORTS_DIR, "summary.json")

    if os.path.exists(summary_path):
        with open(summary_path) as f:
            data = json.load(f)

        return {
            "secrets": data.get("secrets", 0),
            "sast": data.get("sast", 0),
            "cve": data.get("cve", 0),
            "iac": data.get("iac", 0),
            "risk_score": data.get("risk_score", 0),
            "status": data.get("status", "PASS")
        }

    return {
        "secrets": 0,
        "sast": 0,
        "cve": 0,
        "iac": 0,
        "risk_score": 0
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


@app.get("/api/report/{type}")
def get_report(type: str):

    files = {
        "secrets": "secrets.json",
        "sast": "sast.json",
        "cve": "trivy.txt",
        "iac": "iac.txt"
    }

    if type not in files:
        return {"error": "Invalid report"}

    path = os.path.join(REPORTS_DIR, files[type])

    if not os.path.exists(path):
        return {"data": "Report not found"}

    with open(path) as f:
        return {"data": f.read()}
