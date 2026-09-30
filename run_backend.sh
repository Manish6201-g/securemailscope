#!/bin/bash
echo "Starting SecureMailScope Backend (FastAPI)..."
./venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
