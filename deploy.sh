#!/bin/bash
set -e

echo "========================================================"
echo "   SecureMailScope: Automated Deployment Script        "
echo "   SIH26159 | Team AlgoMaster                         "
echo "========================================================"

# 1. Check Python and Node
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required. Aborting." >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo "Node.js is required. Aborting." >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "npm is required. Aborting." >&2; exit 1; }

# 2. Setup Virtual Environment
if [ ! -d "venv" ]; then
    echo "[+] Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "[+] Installing backend dependencies..."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# 3. Build Frontend Assets
echo "[+] Building frontend production bundle..."
cd frontend
npm config set registry https://registry.npmmirror.com/
npm install
npm run build
cd ..

# 4. Create directories
mkdir -p backend/uploads backend/data

# 5. Pre-flight PCAP verification
echo "[+] Generating baseline validation datasets..."
./venv/bin/python3 backend/core/sample_generator.py

# 6. Check for .env
if [ ! -f ".env" ]; then
    echo "[+] Creating .env from .env.example..."
    cp .env.example .env
fi

echo ""
echo "========================================================"
echo "   Deployment Build Succeeded!                         "
echo "========================================================"
echo ""
echo "Option A: Run standalone production server:"
echo "   ./venv/bin/gunicorn backend.main:app -w 2 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000"
echo ""
echo "Option B: Run with Docker Compose:"
echo "   docker compose up --build -d"
echo ""
echo "Access the dashboard at http://localhost:8000"
