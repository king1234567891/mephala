<p align="center">
  <img src="https://img.shields.io/badge/👁️-SHADOWLURE-0d1117?style=for-the-badge&labelColor=ff0040" alt="ShadowLure"/>
</p>

<h1 align="center">
  <code style="color: #ff0040;">⬡ ShadowLure ⬡</code>
</h1>

<p align="center">
  <strong>Advanced Deception Platform with ML-Powered Threat Intelligence</strong>
</p>

<p align="center">
  <sub>
    <em>"In the shadows, we watch. In the lure, they fall."</em>
  </sub>
</p>

<br/>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-ff0040?style=flat-square&logo=python&logoColor=white&labelColor=0d1117" alt="Python"/>
  <img src="https://img.shields.io/badge/asyncio-native-ff0040?style=flat-square&logo=python&logoColor=white&labelColor=0d1117" alt="AsyncIO"/>
  <img src="https://img.shields.io/badge/fastapi-0.108+-ff0040?style=flat-square&logo=fastapi&logoColor=white&labelColor=0d1117" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/vue.js-3.4+-ff0040?style=flat-square&logo=vue.js&logoColor=white&labelColor=0d1117" alt="Vue.js"/>
  <img src="https://img.shields.io/badge/docker-ready-ff0040?style=flat-square&logo=docker&logoColor=white&labelColor=0d1117" alt="Docker"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-155_passing-00ff88?style=flat-square&labelColor=0d1117" alt="Tests"/>
  <img src="https://img.shields.io/badge/ML-Random_Forest-00d4ff?style=flat-square&labelColor=0d1117" alt="ML"/>
  <img src="https://img.shields.io/badge/license-MIT-ff0040?style=flat-square&labelColor=0d1117" alt="License"/>
</p>

<br/>

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██╗     ██╗   ██╗██████╗███████╗   │
│   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██║     ██║   ██║██╔══██╗██╔════╝  │
│   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██║     ██║   ██║██████╔╝█████╗    │
│   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║     ██║   ██║██╔══██╗██╔══╝    │
│   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████╗╚██████╔╝██║  ██║███████╗  │
│   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝  │
│                                                                             │
│                    [ DECEPTION WARFARE SYSTEM v1.0 ]                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ◈ Overview

**ShadowLure** is a high-interaction deception platform engineered to simulate vulnerable network services, harvest attack intelligence, and classify threats in real-time using machine learning.

```
                              ┌──────────────┐
                              │   ATTACKER   │
                              └──────┬───────┘
                                     │
                    ┌────────────────┼────────────────┐
                    ▼                ▼                ▼
             ┌──────────┐     ┌──────────┐     ┌──────────┐
             │   SSH    │     │   HTTP   │     │   FTP    │
             │  :2222   │     │  :8080   │     │  :2121   │
             │ ◉ TRAP   │     │ ◉ TRAP   │     │ ◉ TRAP   │
             └────┬─────┘     └────┬─────┘     └────┬─────┘
                  │                │                │
                  └────────────────┼────────────────┘
                                   ▼
                         ┌─────────────────┐
                         │  ⚡ ML ENGINE   │
                         │  Classification │
                         │  Anomaly Detect │
                         └────────┬────────┘
                                  ▼
                    ┌─────────────────────────┐
                    │     ◈ SHADOWLURE DB     │
                    │  PostgreSQL + Redis     │
                    └─────────────┬───────────┘
                                  ▼
                         ┌────────────────┐
                         │   DASHBOARD    │
                         │   Real-time    │
                         │   Intelligence │
                         └────────────────┘
```

---

## ◈ Arsenal

<table>
<tr>
<td width="50%">

### 🔐 SSH Deception
```
◉ Credential harvesting
◉ Fake shell (25+ commands)
◉ Virtual filesystem
◉ Session recording
◉ Payload detection
```

</td>
<td width="50%">

### 🌐 HTTP Deception
```
◉ WordPress simulation
◉ phpMyAdmin traps
◉ SQLi/XSS/RCE detection
◉ File upload capture
◉ Request forensics
```

</td>
</tr>
<tr>
<td width="50%">

### 📁 FTP Deception
```
◉ Anonymous access traps
◉ Passive/Active modes
◉ Malware quarantine
◉ Transfer logging
◉ Directory traversal detection
```

</td>
<td width="50%">

### 🧠 ML Classification
```
◉ Random Forest classifier
◉ Isolation Forest anomaly
◉ Real-time threat scoring
◉ Auto-labeling pipeline
◉ Model versioning
```

</td>
</tr>
</table>

---

## ◈ Deployment

### Docker (Recommended)

```bash
# Clone
git clone https://github.com/ind4skylivey/shadowlure.git
cd shadowlure

# Configure
cp .env.example .env
nano .env  # Set your secrets

# Deploy
cd docker && docker-compose up -d

# Monitor
docker-compose logs -f shadowlure
```

### Manual

```bash
git clone https://github.com/ind4skylivey/shadowlure.git
cd shadowlure

# Setup
chmod +x scripts/setup.sh && ./scripts/setup.sh

# Database
alembic upgrade head

# Launch (3 terminals)
python core/honeypot.py                        # Honeypots
uvicorn api.server:app --reload --port 8000    # API
cd dashboard && npm install && npm run dev     # Dashboard
```

---

## ◈ Architecture

```
shadowlure/
├── core/                   # ◈ System nucleus
│   ├── base_service.py     #   Abstract honeypot class
│   ├── config.py           #   Pydantic configuration
│   ├── database.py         #   SQLAlchemy async ORM
│   ├── honeypot.py         #   Main orchestrator
│   └── logger.py           #   Structured logging
│
├── services/               # ◈ Deception layer
│   ├── ssh_honeypot.py     #   SSH with asyncssh
│   ├── http_honeypot.py    #   HTTP with aiohttp
│   ├── ftp_honeypot.py     #   FTP with asyncio
│   └── utils/              #   Fake FS, templates
│
├── ml/                     # ◈ Intelligence engine
│   ├── preprocessor.py     #   Feature extraction
│   ├── models.py           #   RF + Isolation Forest
│   ├── trainer.py          #   Training pipeline
│   └── predictor.py        #   Real-time classification
│
├── api/                    # ◈ Command interface
│   ├── server.py           #   FastAPI factory
│   ├── auth.py             #   JWT authentication
│   └── routes/             #   REST endpoints
│
├── dashboard/              # ◈ Tactical display
│   └── src/
│       ├── components/     #   UI components
│       ├── views/          #   Pages
│       └── stores/         #   State management
│
└── docker/                 # ◈ Containerization
    ├── Dockerfile          #   Multi-stage build
    └── docker-compose.yml  #   Orchestration
```

---

## ◈ Threat Classification

| Type | Indicator | Severity |
|:-----|:----------|:--------:|
| `reconnaissance` | Port scanning, enumeration | 🟢 |
| `brute_force` | Credential stuffing | 🟡 |
| `sql_injection` | Database manipulation | 🔴 |
| `xss` | Cross-site scripting | 🟡 |
| `rce` | Remote code execution | ⚫ |
| `path_traversal` | Directory escape | 🟠 |
| `credential_theft` | Password harvesting | 🟠 |

---

## ◈ API Endpoints

```bash
# Authentication
POST /api/v1/auth/login     # Get JWT token

# Intelligence
GET  /api/v1/attacks        # List attacks (paginated)
GET  /api/v1/attacks/{id}   # Attack details
POST /api/v1/attacks/search # Advanced search

# Analytics
GET  /api/v1/stats/overview    # Dashboard stats
GET  /api/v1/stats/timeline    # Attack frequency
GET  /api/v1/stats/geographic  # Geo distribution

# Real-time
WS   /ws/live               # WebSocket feed
```

---

## ◈ Access Points

| Service | Port | Description |
|:--------|:----:|:------------|
| SSH Trap | `2222` | Credential harvester |
| HTTP Trap | `8080` | Web attack detector |
| FTP Trap | `2121` | File transfer monitor |
| API | `8000` | REST interface |
| Dashboard | `3000` | Tactical display |

---

## ◈ Testing

```bash
# Full suite
pytest tests/ -v

# With coverage
pytest tests/ --cov=core --cov=services --cov=ml

# Results: 155 tests passing ✓
```

---

## ◈ Legal

```
⚠️  AUTHORIZED USE ONLY

This software is designed for:
  → Security research on owned infrastructure
  → Authorized penetration testing
  → Educational purposes

Deploy only on networks you own or have explicit permission.
The authors assume no liability for misuse.
```

---

## ◈ License

```
MIT License
Copyright (c) 2024 ind4skylivey
```

---

<p align="center">
  <sub>
    <strong>◈ ShadowLure ◈</strong><br/>
    <em>Deception is the art of war.</em>
  </sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Built_by-ind4skylivey-ff0040?style=for-the-badge&labelColor=0d1117"/>
</p>
