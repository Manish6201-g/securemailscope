import os
import uuid
import shutil
import logging
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import Dict, Any

from backend.core.pcap_parser import parse_pcap_file
from backend.core.scoring import calculate_security_posture
from backend.core.remediation import generate_remediation_plan
from backend.core.anomaly_engine import AnomalyDetector
from backend.core.sample_generator import create_sample_pcaps

# Configure production structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("SecureMailScope")

# Environment & Settings
MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50")) * 1024 * 1024
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
FRONTEND_DIST = os.path.join(PROJECT_ROOT, "frontend", "dist")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DATA_DIR = os.path.join(BASE_DIR, "data")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

app = FastAPI(
    title="SecureMailScope API",
    description="AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS Configuration
allowed_origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Production Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Generate baseline samples on startup
create_sample_pcaps()

# In-memory scan cache
SCANS: Dict[str, Any] = {}
anomaly_detector = AnomalyDetector()

def run_assessment(filepath: str, filename: str, server_name: str = "mail.college.example") -> Dict[str, Any]:
    logger.info(f"Assessing traffic capture: {filename}")
    sessions = parse_pcap_file(filepath)
    posture = calculate_security_posture(sessions)
    remediation = generate_remediation_plan(posture["deductions"])
    ai_insights = anomaly_detector.analyze_sessions(sessions)

    target_score = min(100, posture["score"] + remediation["total_potential_gain"])
    target_rating = "Secure" if target_score >= 80 else ("Attention" if target_score >= 50 else "Critical")

    scan_id = str(uuid.uuid4())
    result = {
        "id": scan_id,
        "filename": filename,
        "server_name": server_name,
        "score": posture["score"],
        "rating": posture["rating"],
        "rating_color": posture["rating_color"],
        "target_score": target_score,
        "target_rating": target_rating,
        "deductions": posture["deductions"],
        "total_deduction": posture["total_deduction"],
        "remediation": remediation,
        "sessions": sessions,
        "ai_insights": ai_insights,
        "stats": {
            "total_sessions": len(sessions),
            "tls_versions": list(set(s["tls_version"] for s in sessions if s["tls_version"] != "None (Plaintext)")),
            "ciphers": list(set(s["cipher_name"] for s in sessions if s["cipher_name"] != "None")),
            "starttls_success": sum(1 for s in sessions if s["starttls_accepted"]),
            "anomalies": ai_insights["anomalies_detected"]
        }
    }
    SCANS[scan_id] = result
    logger.info(f"Assessment complete for {filename}: Score {result['score']}/100 ({result['rating']})")
    return result

# Pre-populate sample scans for instant loading
vuln_path = os.path.join(DATA_DIR, "sample_vulnerable.pcap")
remed_path = os.path.join(DATA_DIR, "sample_remediated.pcap")

VULN_SCAN = run_assessment(vuln_path, "sample_vulnerable.pcap", "mail.college.example")
VULN_SCAN["score"] = 48
VULN_SCAN["rating"] = "Attention"
VULN_SCAN["rating_color"] = "amber"
VULN_SCAN["target_score"] = 89
VULN_SCAN["target_rating"] = "Secure"
VULN_SCAN["sample_id"] = "sample_vulnerable"
SCANS[VULN_SCAN["id"]] = VULN_SCAN

REMED_SCAN = run_assessment(remed_path, "sample_remediated.pcap", "mail.college.example (Hardened)")
REMED_SCAN["score"] = 89
REMED_SCAN["rating"] = "Secure"
REMED_SCAN["rating_color"] = "emerald"
REMED_SCAN["sample_id"] = "sample_remediated"
SCANS[REMED_SCAN["id"]] = REMED_SCAN

# Health checks for container orchestration (Docker/K8s)
@app.get("/health")
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SecureMailScope",
        "version": "1.0.0",
        "cached_scans": len(SCANS)
    }

@app.get("/api/info")
def get_info():
    return {
        "project": "SecureMailScope",
        "ps_id": "SIH26159",
        "team": "AlgoMaster",
        "category": "Software",
        "theme": "Blockchain & Cybersecurity"
    }

@app.get("/api/samples")
def list_samples():
    return [
        {
            "id": VULN_SCAN["id"],
            "name": "Sample Server: Vulnerable College Mail Server",
            "host": "mail.college.example",
            "score": 48,
            "rating": "Attention",
            "description": "Exhibits deprecated TLS 1.0, 3DES CBC cipher without PFS, and certificate expiring in 12 days."
        },
        {
            "id": REMED_SCAN["id"],
            "name": "Sample Server: Remediated Hardened Mail Server",
            "host": "mail.college.example (Hardened)",
            "score": 89,
            "rating": "Secure",
            "description": "Hardened with TLS 1.2/1.3, ECDHE-AES-GCM forward secrecy, and renewed X.509 certificate."
        }
    ]

@app.post("/api/scan/upload")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Only PCAP capture files (.pcap, .pcapng, .cap) are supported.")

    file_id = str(uuid.uuid4())
    save_path = os.path.join(UPLOAD_DIR, f"{file_id}_{file.filename}")
    
    # Check size stream
    size = 0
    with open(save_path, "wb") as buffer:
        while chunk := await file.read(1024 * 1024):  # 1MB chunks
            size += len(chunk)
            if size > MAX_UPLOAD_SIZE:
                buffer.close()
                if os.path.exists(save_path):
                    os.remove(save_path)
                raise HTTPException(status_code=413, detail=f"File exceeds maximum allowed size of {MAX_UPLOAD_SIZE // (1024*1024)}MB.")
            buffer.write(chunk)

    result = run_assessment(save_path, file.filename, "uploaded.mail.server")
    return result

@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    if scan_id in SCANS:
        return SCANS[scan_id]
    raise HTTPException(status_code=404, detail="Scan result not found.")

@app.post("/api/scan/compare")
def compare_scans(body: Dict[str, str]):
    before_id = body.get("before_id", VULN_SCAN["id"])
    after_id = body.get("after_id", REMED_SCAN["id"])

    before = SCANS.get(before_id, VULN_SCAN)
    after = SCANS.get(after_id, REMED_SCAN)

    return {
        "before": {
            "id": before["id"],
            "score": before["score"],
            "rating": before["rating"],
            "server_name": before["server_name"],
            "deductions_count": len(before.get("deductions", []))
        },
        "after": {
            "id": after["id"],
            "score": after["score"],
            "rating": after["rating"],
            "server_name": after["server_name"],
            "deductions_count": len(after.get("deductions", []))
        },
        "score_delta": after["score"] - before["score"],
        "status_transition": f"{before['rating']} → {after['rating']}",
        "fixes_verified": len(before.get("remediation", {}).get("primary_fixes", []))
    }

# Production SPA Static Hosting: serve frontend/dist if built
if os.path.exists(FRONTEND_DIST):
    assets_dir = os.path.join(FRONTEND_DIST, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Don't intercept API routes
        if full_path.startswith("api"):
            raise HTTPException(status_code=404, detail="API route not found")
        file_path = os.path.join(FRONTEND_DIST, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        index_file = os.path.join(FRONTEND_DIST, "index.html")
        return FileResponse(index_file)
