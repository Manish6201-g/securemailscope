# SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment

**Smart India Hackathon 2026**  
- **Problem Statement ID:** SIH26159  
- **Theme:** Blockchain & Cybersecurity  
- **Team ID:** 133192  
- **Team Name:** AlgoMaster  
- **Tagline:** *"Evidence → Explain → Prioritise → Remediate → Re-scan: the fix, proven."*

---

## 📌 Overview

**SecureMailScope** passively inspects email server traffic (SMTP, IMAP, POP3) without decrypting message contents. It evaluates TLS version negotiations, cipher strength, forward secrecy (PFS), certificate health, and STARTTLS state transitions against **NIST SP 800-52r2**, **RFC 8314**, **RFC 3207**, and **RFC 8461 (MTA-STS)**.

---

## 🚀 Production Deployment Options

SecureMailScope is engineered as a **unified, self-contained service**. The FastAPI backend automatically serves the compiled Vite + React single-page application and static assets from a single port (`8000`), eliminating CORS configuration issues in production.

---

### Option 1: One-Command Automated Deployment Script

Run the automated pre-flight setup and build script:
```bash
chmod +x deploy.sh
./deploy.sh
```
Then start the production Gunicorn server:
```bash
./venv/bin/gunicorn backend.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```
Visit: [http://localhost:8000](http://localhost:8000)

---

### Option 2: Docker Compose (Recommended for Production)

Run the full stack inside an isolated, containerized environment:
```bash
# Build and run in detached mode
docker compose up --build -d

# View real-time logs
docker compose logs -f

# Check container health status
docker compose ps
```
The application will be live at [http://localhost:8000](http://localhost:8000) with automatic container restarts and healthcheck probes.

---

### Option 3: Standalone Docker Container

```bash
# 1. Build the multi-stage image
docker build -t securemailscope:latest .

# 2. Run container with upload volume persistence
docker run -d \
  -p 8000:8000 \
  --name securemailscope \
  -e MAX_UPLOAD_SIZE_MB=50 \
  securemailscope:latest
```

---

### Option 4: Linux Systemd Service (Institutional On-Prem / VM Deployment)

For persistent deployment on college, government, or SME Linux servers (Ubuntu/Debian/CentOS/RHEL):

1. Copy the project to `/opt/securemailscope`:
   ```bash
   sudo cp -r . /opt/securemailscope
   cd /opt/securemailscope
   ./deploy.sh
   ```

2. Install and enable the systemd unit:
   ```bash
   sudo cp securemailscope.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now securemailscope
   ```

3. Check service status:
   ```bash
   sudo systemctl status securemailscope
   ```

---

### Option 5: Nginx Reverse Proxy with Rate Limiting & SSL

Use the included `nginx/nginx.conf` for reverse-proxying behind standard Nginx:
- Gzip compression for fast asset delivery
- `limit_req_zone` rate-limiting (10 req/s, burst 20) on API endpoints
- Large capture streaming up to 50MB (`client_max_body_size 50M`)

---

## 🔒 Production Security Hardening Included

- **Security Headers Middleware:** Automatic injection of `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`, and `Referrer-Policy`.
- **Zero-Decryption Design:** Handshake metadata only. Raw email message bodies are never parsed, decrypted, or written to disk.
- **Upload Payload Guard:** Enforces strict 50MB file size limit to prevent memory exhaustion / DoS attacks.
- **Health Probes:** Active `/health` and `/api/health` endpoints for Kubernetes, Docker, and uptime monitors.
- **Structured Logging:** Standardized timestamped logging with log levels for SIEM/audit ingestion.

---

## 🛠️ Development Mode (Live Hot-Reload)

```bash
# Terminal 1: Backend
./venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Frontend
cd frontend
npm run dev
```
Development Dashboard: [http://localhost:5173](http://localhost:5173)  
Backend API Documentation: [http://localhost:8000/api/docs](http://localhost:8000/api/docs)
