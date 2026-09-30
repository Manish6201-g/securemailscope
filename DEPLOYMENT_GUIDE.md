# 🚀 SecureMailScope: Comprehensive Production Deployment Guide

**Smart India Hackathon 2026** | **Problem Statement:** SIH26159  
**Team ID:** 133192 | **Team Name:** AlgoMaster  
**System:** AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications  

---

## 📋 Table of Contents
1. [System Requirements & Architecture](#1-system-requirements--architecture)
2. [Quick Deployment with Docker & Docker Compose (Recommended)](#2-quick-deployment-with-docker--docker-compose-recommended)
3. [Native Linux Server Deployment (Systemd + Gunicorn)](#3-native-linux-server-deployment-systemd--gunicorn)
4. [Cloud VM Deployment (AWS EC2, DigitalOcean, Azure, Linode)](#4-cloud-vm-deployment-aws-ec2-digitalocean-azure-linode)
5. [Free / Low-Cost PaaS Deployment (Render / Railway / Fly.io)](#5-free--low-cost-paas-deployment-render--railway--flyio)
6. [Nginx Reverse Proxy & SSL Setup (Let's Encrypt)](#6-nginx-reverse-proxy--ssl-setup-lets-encrypt)
7. [Passive Traffic Mirroring / TAP Setup (Campus / Enterprise)](#7-passive-traffic-mirroring--tap-setup-campus--enterprise)
8. [Environment Variables Reference](#8-environment-variables-reference)
9. [Pre-Flight Verification & Health Monitoring](#9-pre-flight-verification--health-monitoring)
10. [Troubleshooting & FAQ](#10-troubleshooting--faq)
11. [Hackathon Demo & Evaluator Quickstart Script](#11-hackathon-demo--evaluator-quickstart-script)

---

## 1. System Requirements & Architecture

### Minimum Hardware Requirements
| Resource | Minimum (Evaluation / Lab) | Recommended (Campus / Production) |
| :--- | :--- | :--- |
| **CPU** | 2 vCPU / Cores | 4 vCPU / Cores |
| **RAM** | 2 GB RAM | 4–8 GB RAM |
| **Storage** | 10 GB SSD | 50 GB SSD (for PCAP archives) |
| **Operating System** | Ubuntu 22.04 / 24.04 LTS, Debian 12, RHEL 9, macOS | Ubuntu 22.04 / 24.04 LTS |

### Software Prerequisites
- **Docker Engine** $\ge 24.0$ & **Docker Compose** $\ge 2.20$ (for containerized setup)
- *OR* **Python** $\ge 3.10$ & **Node.js** $\ge 18.0$ (for bare-metal setup)

### Production Topology
```
                  [ Incoming Mail Traffic / Mirror Port ]
                                    │
                                    ▼
                [ Nginx Reverse Proxy (SSL / Rate Limit) ]
                     Port 80 / 443 (Let's Encrypt)
                                    │
                                    ▼
                  [ SecureMailScope Container / Process ]
                                Port 8000
        ┌───────────────────────────┴───────────────────────────┐
        ▼                                                       ▼
 [ FastAPI REST API ]                                [ React SPA UI (Vite) ]
  • Zero-Decryption PCAP Parser                       • Slide 4 Ranked Fixes
  • NIST SP 800-52r2 Rules Engine                     • Before vs After Visualizer
  • Isolation Forest Anomaly Engine                   • Frame Telemetry Inspector
  • Remediation Config Generator                      • CERT-In Export Engine
```

---

## 2. Quick Deployment with Docker & Docker Compose (Recommended)

Docker is the easiest and most reliable method to run SecureMailScope in an isolated, production-grade environment.

### Step 1: Clone the Repository
```bash
git clone https://github.com/<your-organization>/SecureMailScope.git
cd SecureMailScope
```

### Step 2: Configure Environment
```bash
cp .env.example .env
```
*(Optional)* Edit `.env` to adjust limits (e.g. `MAX_UPLOAD_SIZE_MB=50`).

### Step 3: Build & Launch Containers
```bash
docker compose up --build -d
```

### Step 4: Verify Deployment
```bash
# Check container status
docker compose ps

# View live application logs
docker compose logs -f
```
The application will be running at **`http://<SERVER_IP>:8000`**.

---

## 3. Native Linux Server Deployment (Systemd + Gunicorn)

For deploying directly on an institutional Linux server or virtual machine running Ubuntu or Debian:

### Step 1: Clone and Run the Automated Setup
```bash
git clone https://github.com/<your-organization>/SecureMailScope.git /opt/securemailscope
cd /opt/securemailscope
chmod +x deploy.sh
./deploy.sh
```

### Step 2: Configure Systemd Service
```bash
sudo cp securemailscope.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now securemailscope
```

### Step 3: Check Service Health
```bash
sudo systemctl status securemailscope
```

To view live systemd logs:
```bash
sudo journalctl -u securemailscope -f
```

---

## 4. Cloud VM Deployment (AWS EC2, DigitalOcean, Azure, Linode)

### AWS EC2 Deployment Steps
1. **Launch an Instance**:
   - AMI: Ubuntu Server 24.04 LTS (64-bit Arm or x86)
   - Instance Type: `t3.small` or `t3.medium` (2 vCPU, 2–4 GB RAM)
   - Storage: 20 GB gp3
2. **Security Group Inbound Rules**:
   - `SSH` (Port 22) -> Your IP
   - `HTTP` (Port 80) -> `0.0.0.0/0`
   - `HTTPS` (Port 443) -> `0.0.0.0/0`
   - `Custom TCP` (Port 8000) -> `0.0.0.0/0` (if accessing directly without Nginx)
3. **SSH into the instance and run**:
   ```bash
   sudo apt update && sudo apt install -y docker.io docker-compose-v2 git
   sudo usermod -aG docker ubuntu
   # Log out and log back in, then:
   git clone https://github.com/<your-username>/SecureMailScope.git
   cd SecureMailScope
   docker compose up --build -d
   ```

---

## 5. Free / Low-Cost PaaS Deployment (Render / Railway / Fly.io)

### Deploying to Render
1. Push your repository to GitHub.
2. Sign in to [Render](https://render.com) and click **New +** -> **Web Service**.
3. Select your repository.
4. Set Environment to **Docker** (Render will automatically detect the root `Dockerfile`).
5. Set Plan to **Free** or **Starter**.
6. Under Environment Variables:
   - `PORT` = `8000`
   - `MAX_UPLOAD_SIZE_MB` = `50`
7. Click **Create Web Service**. Render builds the multi-stage image and issues a free HTTPS URL (e.g. `https://securemailscope.onrender.com`).

---

## 6. Nginx Reverse Proxy & SSL Setup (Let's Encrypt)

To serve SecureMailScope securely on a standard domain with HTTPS (`https://securemailscope.college.edu`):

### Step 1: Install Nginx & Certbot
```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
```

### Step 2: Configure Virtual Host
Create `/etc/nginx/sites-available/securemailscope`:
```nginx
server {
    listen 80;
    server_name mailscope.yourdomain.edu;

    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the configuration:
```bash
sudo ln -s /etc/nginx/sites-available/securemailscope /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Step 3: Issue Free SSL Certificate
```bash
sudo certbot --nginx -d mailscope.yourdomain.edu
```
Certbot will configure SSL automatically with automatic renewals.

---

## 7. Passive Traffic Mirroring / TAP Setup (Campus / Enterprise)

As highlighted in **Slide 3 of the SIH pitch deck**, SecureMailScope performs **passive, zero-decryption** analysis.

### Option A: SPAN / Mirror Port Capture
Configure your core switch or router to mirror mail server traffic (Ports 25, 465, 587, 110, 995, 143, 993) to a monitoring interface:

```bash
# Capture 10 minutes of mail traffic on eth1 interface without decrypting:
sudo tcpdump -i eth1 -s 0 -w /opt/securemailscope/captures/mail_traffic_$(date +%F).pcap \
  "port 25 or port 465 or port 587 or port 110 or port 995 or port 143 or port 993"
```
Once recorded, upload the `.pcap` directly via the SecureMailScope Web UI or API.

### Option B: Automated Daily Scheduled Scan via Cron
Run a cron job that captures 5-minute traffic samples and submits them to the API:
```bash
# In crontab -e
0 * * * * /usr/bin/tcpdump -i eth1 -s 0 -w /tmp/hourly.pcap -G 300 -W 1 "port 25 or port 587" && \
          curl -F "file=@/tmp/hourly.pcap" http://127.0.0.1:8000/api/scan/upload
```

---

## 8. Environment Variables Reference

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `HOST` | `0.0.0.0` | Bind IP address for the server. |
| `PORT` | `8000` | Port on which the FastAPI/Gunicorn server listens. |
| `MAX_UPLOAD_SIZE_MB` | `50` | Maximum allowable PCAP file upload size in Megabytes. |
| `ALLOWED_ORIGINS` | `*` | Comma-separated list of CORS allowed origins for API calls. |
| `ENVIRONMENT` | `production` | Environment mode (`development` or `production`). |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |

---

## 9. Pre-Flight Verification & Health Monitoring

### 1. Health Probe
Test that the service is running and responsive:
```bash
curl -s http://localhost:8000/health | jq .
```
**Expected Response:**
```json
{
  "status": "healthy",
  "service": "SecureMailScope",
  "version": "1.0.0",
  "cached_scans": 2
}
```

### 2. Verify Sample Datasets
Verify that the NIST SP 800-52r2 baseline scenarios are loaded:
```bash
curl -s http://localhost:8000/api/samples | jq .
```

---

## 10. Troubleshooting & FAQ

### Q1: `Address already in use: 8000`
Another service is using port 8000. Either change `PORT=8080` in `.env` or terminate the conflicting process:
```bash
sudo lsof -i :8000
sudo kill -9 <PID>
```

### Q2: `File exceeds maximum allowed size`
Increase the maximum upload size in `.env`:
```env
MAX_UPLOAD_SIZE_MB=100
```
Then restart the service (`docker compose restart` or `sudo systemctl restart securemailscope`). If using Nginx, ensure `client_max_body_size 100M;` is updated as well.

### Q3: How is privacy ensured?
SecureMailScope only parses packet headers and TLS record frames (`ContentType 0x16`, `ServerHello`, Cipher IDs). Email message bodies (`DATA`, MIME attachments) are ignored and never written to logs or disk.

---

## 11. Hackathon Demo & Evaluator Quickstart Script

When presenting to SIH evaluators, follow this 2-minute demonstration flow:

1. **Open the Dashboard**: Navigate to `http://localhost:8000`.
2. **Demonstrate Raw Telemetry (Slide 4)**:
   - Click **"Load Scenario: mail.college.example (48 pts)"**.
   - Show the **Email Security Score: 48 / 100** (*Attention* rating).
3. **Show "Fix This First" (Actionable AI Guidance)**:
   - Highlight the #1 ranked action: **Disable TLS 1.0 / 1.1** `(+18 pts)`.
   - Toggle between **Postfix** and **Exim** tabs.
   - Click the **Copy** button on the configuration snippet to show drop-in readiness.
4. **Demonstrate Re-Scan Proof**:
   - Click **"Compare Re-Scan Proof"**.
   - Show the before vs. after comparison chart: **48 $\rightarrow$ 89 (+41 Points Gained)**, transitioning from *Attention $\rightarrow$ Secure*.
5. **Show Zero-Decryption Evidence**:
   - Switch to **"Traffic & Handshake Inspector"** tab to show frame numbers, negotiated ciphers, and STARTTLS state transitions.
6. **Show Institutional Compliance**:
   - Switch to **"CERT-In Audit Report"** tab and click **"Print / Export PDF"** to demonstrate automated 1-click reporting.
