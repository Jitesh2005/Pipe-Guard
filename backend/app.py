from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import json
import os

app = FastAPI(title="PipeGuard")

BASE_DIR = os.path.dirname(__file__)
REPORTS_DIR = os.path.join(BASE_DIR, "..", "reports")

# Serve static dashboard files
app.mount("/static", StaticFiles(directory="dashboard"), name="static")

@app.get("/")
def root():
    return FileResponse("dashboard/index.html")

@app.get("/api/status")
def status():
    path = os.path.join(REPORTS_DIR, "summary.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"status": "NO DATA"}

@app.get("/api/history")
def history():
    path = os.path.join(REPORTS_DIR, "history.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []
