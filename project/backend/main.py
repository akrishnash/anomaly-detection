import os
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import uvicorn

# Ensure the backend directory is in the import path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import database
import train_models
import api

app = FastAPI(title="Cybersecurity Intrusion Detection System (IDS) API")

# Enable CORS for frontend connectivity
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include the API routes
app.include_router(api.router)

# Mount the frontend's production static build folder if it exists
frontend_dist_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
if os.path.exists(frontend_dist_path):
    app.mount("/", StaticFiles(directory=frontend_dist_path, html=True), name="frontend")
else:
    # Fallback endpoint if static build not compiled yet
    @app.get("/")
    def read_root():
        return {"status": "running", "message": "FastAPI Cybersecurity IDS backend active. Start frontend client via Vite dev server."}

@app.on_event("startup")
def startup_event():
    # 1. Initialize SQLite Database tables
    database.init_db()
    
    # 2. Check if baseline ML models are trained
    models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
    required_assets = ["scaler.pkl", "isolation_forest.pkl", "autoencoder.pkl", "meta.pkl"]
    
    missing_assets = [asset for asset in required_assets if not os.path.exists(os.path.join(models_dir, asset))]

    # Older meta.pkl files predate the unsupervised ensemble calibration; force retrain
    if not missing_assets:
        try:
            import pickle
            with open(os.path.join(models_dir, "meta.pkl"), "rb") as f:
                if "calibration" not in pickle.load(f):
                    missing_assets = ["meta.pkl (no ensemble calibration)"]
        except Exception:
            missing_assets = ["meta.pkl (unreadable)"]

    if missing_assets:
        database.add_log("WARNING", f"Missing trained model files: {missing_assets}. Training models now...")
        success = train_models.train_and_save_models()
        if success:
            database.add_log("INFO", "Baseline ML models trained and loaded successfully.")
        else:
            database.add_log("ERROR", "Model training on startup failed.")
    else:
        database.add_log("INFO", "Trained models detected. Skipping startup training.")

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
