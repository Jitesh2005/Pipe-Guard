'''from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import json
import os

app = FastAPI(title="PipeGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORTS_DIR = "../reports"

def load_report(filename):
    path = os.path.join(REPORTS_DIR, filename)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}

@app.get("/status")
def pipeline_status():
    return {
        "secrets": os.path.exists(f"{REPORTS_DIR}/secrets.json"),
        "sast": os.path.exists(f"{REPORTS_DIR}/sast.json"),
        "cve": os.path.exists(f"{REPORTS_DIR}/trivy.txt"),
        "iac": os.path.exists(f"{REPORTS_DIR}/iac.txt"),
        "sbom": os.path.exists(f"{REPORTS_DIR}/sbom.xml")
    }

@app.get("/reports/secrets")
def secrets():
    return load_report("secrets.json")

@app.get("/reports/sast")
def sast():
    return load_report("sast.json")

@app.get("/")
def root():
    return {
        "service": "PipeGuard API",
        "status": "running",
        "message": "Go to /docs for API documentation"
    }
'''

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import json
import os

app = FastAPI(title="PipeGuard")

BASE_DIR = os.path.dirname(__file__)
REPORTS_DIR = os.path.join(BASE_DIR, "..", "reports")

# Serve dashboard
app.mount("/dashboard", StaticFiles(directory="dashboard"), name="dashboard")

@app.get("/")
def root():
    return FileResponse("dashboard/index.html")

@app.get("/api/status")
def status():
    summary = os.path.join(REPORTS_DIR, "summary.json")
    if os.path.exists(summary):
        with open(summary) as f:
            return json.load(f)
    return {
        "secrets": 0,
        "sast": 0,
        "cve": 0,
        "iac": 0
    }


@app.get("/api/history")
def history():
    hist = os.path.join(REPORTS_DIR, "history.json")
    if os.path.exists(hist):
        with open(hist) as f:
            return json.load(f)
    return []
