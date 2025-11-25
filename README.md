<p align="center">
  <img src="https://img.shields.io/badge/🕷️-MEPHALA-8b5cf6?style=for-the-badge&labelColor=0d0d0d" alt="Mephala"/>
</p>
<img width="1536" height="1024" alt="mephala" src="https://github.com/user-attachments/assets/1ece7e54-3f36-43f9-aaa9-a7aae7a871b8" />

<h1 align="center">
  <code>༺ MEPHALA ༻</code>
</h1>

<p align="center">
  <strong>Daedric Deception Platform</strong><br/>
  <sub>Advanced Honeypot System with ML-Powered Threat Intelligence</sub>
</p>

<br/>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-8b5cf6?style=flat-square&logo=python&logoColor=white&labelColor=0d0d0d" alt="Python"/>
  <img src="https://img.shields.io/badge/asyncio-native-8b5cf6?style=flat-square&logo=python&logoColor=white&labelColor=0d0d0d" alt="AsyncIO"/>
  <img src="https://img.shields.io/badge/fastapi-0.108+-8b5cf6?style=flat-square&logo=fastapi&logoColor=white&labelColor=0d0d0d" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/vue.js-3.4+-8b5cf6?style=flat-square&logo=vue.js&logoColor=white&labelColor=0d0d0d" alt="Vue.js"/>
  <img src="https://img.shields.io/badge/docker-ready-8b5cf6?style=flat-square&logo=docker&logoColor=white&labelColor=0d0d0d" alt="Docker"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-155_passing-a855f7?style=flat-square&labelColor=0d0d0d" alt="Tests"/>
  <img src="https://img.shields.io/badge/ML-Random_Forest-c084fc?style=flat-square&labelColor=0d0d0d" alt="ML"/>
  <img src="https://img.shields.io/badge/license-MIT-8b5cf6?style=flat-square&labelColor=0d0d0d" alt="License"/>
</p>

<br/>

```
                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                      ▄█▀                                                     ▀█▄
                    ▄█▀  ███╗   ███╗███████╗██████╗ ██╗  ██╗ █████╗ ██╗      █████╗  ▀█▄
                   █▀    ████╗ ████║██╔════╝██╔══██╗██║  ██║██╔══██╗██║     ██╔══██╗   ▀█
                  █▌     ██╔████╔██║█████╗  ██████╔╝███████║███████║██║     ███████║    ▐█
                  █▌     ██║╚██╔╝██║██╔══╝  ██╔═══╝ ██╔══██║██╔══██║██║     ██╔══██║    ▐█
                   █▄    ██║ ╚═╝ ██║███████╗██║     ██║  ██║██║  ██║███████╗██║  ██║   ▄█
                    ▀█▄  ╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ▄█▀
                      ▀█▄                                                         ▄█▀
                         ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                                    ╔═════════════════════════════════╗
                                    ║    DAEDRIC PRINCE OF SECRETS    ║
                                    ║       The Webspinner v1.0       ║
                                    ╚═════════════════════════════════╝
```

<br/>

<p align="center">
<table>
<tr>
<td>

```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   "Go now, weave your web across the network.                 ║
║    Let the secrets flow to you.                               ║
║    Let the lies trap the unwary.                              ║
║    The Webspinner watches. The Webspinner waits."             ║
║                                                               ║
║                    — Blessing of Mephala                      ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

</td>
</tr>
</table>
</p>

<br/>

---

## ༺ What is Mephala? ༻

**Mephala** is a high-interaction honeypot that simulates vulnerable network services to **trap attackers** and **harvest intelligence**.

```
┌──────────────┐                                              ┌──────────────┐
│   ATTACKER   │ ──► Thinks it's a real server ──► TRAPPED ──►│  MEPHALA DB  │
└──────────────┘                                              └──────────────┘
                                                                     │
                              Credentials, commands, payloads,       │
                              IPs, techniques, malware samples       │
                                                                     ▼
                                                              ┌──────────────┐
                                                              │  DASHBOARD   │
                                                              │  Real-time   │
                                                              └──────────────┘
```

> Named after the **Daedric Prince of secrets, lies, and webs of deceit** from *The Elder Scrolls V: Skyrim*.

---

## ༺ The Traps ༻

Mephala weaves three deadly threads to ensnare intruders:

| Thread | Port | Disguise | What It Captures |
|:-------|:----:|:---------|:-----------------|
| 🔐 **SSH** | `2222` | Linux OpenSSH server | Usernames, passwords, shell commands, session recordings |
| 🌐 **HTTP** | `8080` | WordPress, phpMyAdmin | SQL injection, XSS attempts, file uploads, request payloads |
| 📁 **FTP** | `2121` | vsftpd file server | Credentials, uploaded malware, directory traversal attempts |

### SSH Trap Features
```
◈ Credential harvesting (username/password capture)
◈ Fake shell with 25+ Linux commands (ls, cat, wget, curl, etc.)
◈ Virtual filesystem (/etc/passwd, /etc/shadow, realistic structure)
◈ Session recording (every keystroke logged)
◈ Malicious command detection (wget, curl, chmod +x patterns)
```

### HTTP Trap Features
```
◈ WordPress login simulation (wp-login.php, wp-admin)
◈ phpMyAdmin honeytokens
◈ SQL injection detection (UNION, SELECT, DROP, etc.)
◈ XSS payload capture (<script>, onerror, javascript:)
◈ RCE attempt detection (;, |, $(), backticks)
◈ File upload quarantine
```

### FTP Trap Features
```
◈ Anonymous and authenticated access
◈ Passive (PASV) and Active (PORT) mode support
◈ Uploaded file capture and quarantine
◈ Directory listing with fake files
◈ Path traversal detection (../, %2e%2e)
```

---

## ༺ The Spider — ML Engine ༻

Every attack is analyzed by Mephala's machine learning brain:

```
                    ┌─────────────────┐
    Attack ────────►│  PREPROCESSOR   │──── Feature Extraction
                    └────────┬────────┘     (TF-IDF, patterns, IP analysis)
                             │
                             ▼
                    ┌─────────────────┐
                    │   CLASSIFIER    │──── Random Forest
                    │  (Random Forest)│     Multi-class classification
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ ANOMALY DETECTOR│──── Isolation Forest
                    │(Isolation Forest)│    Zero-day detection
                    └────────┬────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │  THREAT CLASSIFICATION       │
              │  + Severity Score (1-10)     │
              │  + Confidence Level          │
              └──────────────────────────────┘
```

### Threat Classifications

| Type | Description | Severity |
|:-----|:------------|:--------:|
| `reconnaissance` | Port scanning, service enumeration | 🟢 Low |
| `brute_force` | Credential stuffing, password spraying | 🟡 Medium |
| `sql_injection` | Database manipulation attempts | 🔴 High |
| `xss` | Cross-site scripting payloads | 🟡 Medium |
| `rce` | Remote code execution attempts | ⚫ Critical |
| `path_traversal` | Directory escape attempts | 🟠 High |
| `credential_theft` | Password/token harvesting | 🟠 High |

---

## ༺ The Eye — Dashboard ༻

Real-time visualization of the web's activity:

| View | Description |
|:-----|:------------|
| **Live Feed** | Real-time stream of attacks as they happen |
| **World Map** | Geographic visualization of attack origins (Leaflet) |
| **Timeline** | Attack frequency over time (Chart.js) |
| **Statistics** | Total attacks, unique IPs, severity breakdown |
| **Attack Details** | Deep dive into individual attack sessions |

---

## ༺ Use Cases ༻

| Purpose | Benefit |
|:--------|:--------|
| **Threat Research** | Study real attacker behavior, TTPs, and tools |
| **Threat Intelligence** | Collect IOCs (IPs, payloads, signatures, malware) |
| **Early Warning System** | Detect attackers probing your network before they hit real assets |
| **Deception Defense** | Waste attacker time and resources on fake targets |
| **Security Training** | Learn attack patterns in a safe, controlled environment |
| **SOC Enrichment** | Feed captured data into SIEM/SOAR platforms |

---

## ༺ Architecture ༻

```
mephala/
├── core/                   # ◈ System Core
│   ├── base_service.py     #   Abstract honeypot base class
│   ├── config.py           #   Pydantic configuration management
│   ├── database.py         #   SQLAlchemy async ORM (PostgreSQL/SQLite)
│   ├── honeypot.py         #   Main orchestrator & lifecycle manager
│   └── logger.py           #   Structured logging (JSON/text)
│
├── services/               # ◈ Honeypot Services
│   ├── ssh_honeypot.py     #   SSH trap (asyncssh)
│   ├── http_honeypot.py    #   HTTP trap (aiohttp)
│   ├── ftp_honeypot.py     #   FTP trap (asyncio)
│   └── utils/
│       ├── fake_filesystem.py   # Virtual Linux filesystem
│       ├── response_templates.py # Realistic banners & responses
│       └── session_manager.py    # Session tracking & statistics
│
├── ml/                     # ◈ Machine Learning Pipeline
│   ├── preprocessor.py     #   Feature extraction (TF-IDF, patterns)
│   ├── models.py           #   Random Forest + Isolation Forest
│   ├── trainer.py          #   Training pipeline with GridSearchCV
│   └── predictor.py        #   Real-time classification with caching
│
├── api/                    # ◈ REST API (FastAPI)
│   ├── server.py           #   Application factory, CORS, lifespan
│   ├── auth.py             #   JWT authentication (passlib/bcrypt)
│   ├── models.py           #   Pydantic request/response schemas
│   └── routes/
│       ├── attacks.py      #   CRUD endpoints for attacks
│       ├── stats.py        #   Statistics & analytics endpoints
│       └── websocket.py    #   Real-time WebSocket feed
│
├── dashboard/              # ◈ Frontend (Vue.js 3)
│   └── src/
│       ├── components/     #   StatCard, LiveFeed, Charts
│       ├── views/          #   Dashboard, Attacks, AttackMap
│       ├── stores/         #   Pinia state management
│       └── services/       #   Axios API client
│
├── docker/                 # ◈ Containerization
│   ├── Dockerfile          #   Multi-stage build, non-root user
│   ├── docker-compose.yml  #   Full stack orchestration
│   └── nginx.conf          #   Reverse proxy configuration
│
└── scripts/                # ◈ Utilities
    ├── setup.sh            #   Automated environment setup
    ├── train_models.py     #   ML model training CLI
    └── seed_database.py    #   Test data generation
```

---

## ༺ Quick Start ༻

### Docker (Recommended)

```bash
# Clone the artifact
git clone https://github.com/ind4skylivey/mephala.git
cd mephala

# Configure secrets
cp .env.example .env
nano .env

# Summon the web
cd docker && docker-compose up -d

# Watch the threads
docker-compose logs -f mephala
```

### Manual Installation

```bash
# Clone
git clone https://github.com/ind4skylivey/mephala.git
cd mephala

# Setup environment
chmod +x scripts/setup.sh
./scripts/setup.sh

# Initialize database
alembic upgrade head

# Start services (3 terminals)
python core/honeypot.py                        # Honeypot traps
uvicorn api.server:app --reload --port 8000    # REST API
cd dashboard && npm install && npm run dev     # Dashboard
```

---

## ༺ API Reference ༻

### Authentication
```bash
# Obtain JWT token
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### Endpoints

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/v1/auth/login` | Get JWT access token |
| `GET` | `/api/v1/attacks` | List attacks (paginated, filterable) |
| `GET` | `/api/v1/attacks/{id}` | Get attack details with related data |
| `POST` | `/api/v1/attacks/search` | Advanced search with filters |
| `DELETE` | `/api/v1/attacks/{id}` | Delete attack record |
| `GET` | `/api/v1/stats/overview` | Dashboard statistics |
| `GET` | `/api/v1/stats/timeline` | Attack frequency over time |
| `GET` | `/api/v1/stats/geographic` | Geographic distribution |
| `GET` | `/api/v1/stats/top-attackers` | Most active source IPs |
| `GET` | `/api/v1/stats/attack-types` | Attack type distribution |
| `WS` | `/ws/live` | Real-time attack feed |

---

## ༺ Configuration ༻

### Environment Variables

```bash
# Core
MEPHALA_ENV=production
DEBUG=false

# Database (PostgreSQL recommended)
DATABASE_URL=postgresql+asyncpg://mephala:secret@localhost:5432/mephala

# Cache
REDIS_URL=redis://localhost:6379/0

# API Security
API_SECRET_KEY=your-32-char-secret-key
API_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Service Ports
SSH_PORT=2222
HTTP_PORT=8080
FTP_PORT=2121

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
```

---

## ༺ Tech Stack ༻

| Layer | Technology |
|:------|:-----------|
| **Language** | Python 3.10+ |
| **Async Framework** | asyncio, asyncssh, aiohttp |
| **API** | FastAPI, Uvicorn |
| **Database** | PostgreSQL (async), SQLAlchemy 2.0 |
| **Cache** | Redis |
| **ML** | scikit-learn (Random Forest, Isolation Forest) |
| **Frontend** | Vue.js 3, Pinia, Chart.js, Leaflet |
| **Containerization** | Docker, docker-compose |
| **Reverse Proxy** | nginx |

---

## ༺ Testing ༻

```bash
# Run all tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=core --cov=services --cov=ml --cov=api

# Results
============================= 155 passed ==============================
```

---

## ༺ Why Mephala? ༻

How does Mephala compare to other honeypot frameworks?

| Feature | Mephala | Cowrie | T-Pot | Dionaea | HoneyTrap |
|:--------|:-------:|:------:|:-----:|:-------:|:---------:|
| **SSH Honeypot** | ✅ | ✅ | ✅ | ❌ | ✅ |
| **HTTP Honeypot** | ✅ | ❌ | ✅ | ✅ | ✅ |
| **FTP Honeypot** | ✅ | ❌ | ✅ | ✅ | ✅ |
| **ML Classification** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Anomaly Detection** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Auto Threat Scoring** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Real-time Dashboard** | ✅ Vue.js | ❌ | ✅ Kibana | ❌ | ❌ |
| **WebSocket Live Feed** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **REST API** | ✅ FastAPI | ❌ | ❌ | ❌ | ❌ |
| **Single Codebase** | ✅ Python | ✅ Python | ❌ Multi | ❌ C | ✅ Go |
| **Modern Async** | ✅ asyncio | ❌ Twisted | ❌ | ❌ | ✅ |
| **Lightweight** | ✅ | ✅ | ❌ Heavy | ✅ | ✅ |
| **Easy Deploy** | ✅ | ✅ | ⚠️ Complex | ⚠️ | ✅ |

### What Makes Mephala Unique

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  🧠 ML-POWERED INTELLIGENCE                                         │
│     → Random Forest classifier for attack categorization            │
│     → Isolation Forest for zero-day anomaly detection               │
│     → Automatic severity scoring (1-10)                             │
│     → Real-time threat classification                               │
│                                                                     │
│  ⚡ MODERN ARCHITECTURE                                              │
│     → Pure Python 3.10+ with native asyncio                         │
│     → FastAPI REST endpoints                                        │
│     → WebSocket real-time streaming                                 │
│     → Vue.js 3 reactive dashboard                                   │
│                                                                     │
│  🎯 ALL-IN-ONE SOLUTION                                             │
│     → SSH + HTTP + FTP in single deployment                         │
│     → No Elasticsearch/Kibana dependency                            │
│     → Lightweight compared to T-Pot (~8GB RAM vs ~256MB)            │
│     → Single language, single codebase                              │
│                                                                     │
│  🕷️ UNIQUE IDENTITY                                                  │
│     → Skyrim-inspired Daedric aesthetic                             │
│     → Professional documentation                                    │
│     → Active development                                            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ༺ Roadmap ༻

- [ ] Telnet honeypot
- [ ] SMTP honeypot
- [ ] MySQL/PostgreSQL honeypot
- [ ] Elasticsearch integration
- [ ] Slack/Telegram alerting
- [ ] MITRE ATT&CK mapping
- [ ] Threat feed export (STIX/TAXII)
- [ ] Kubernetes Helm chart

---

## ༺ Warning ༻

```
⚠️  AUTHORIZED USE ONLY

This tool is intended for:
  → Security research on owned infrastructure
  → Authorized penetration testing engagements
  → Educational and training purposes
  → Threat intelligence gathering on controlled networks

Deploy only on networks you own or have explicit written permission to test.
The authors assume no liability for misuse or damage caused by this software.
Unauthorized deployment may violate local laws and regulations.
```

---

## ༺ License ༻

```
MIT License

Copyright (c) 2024 ind4skylivey

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.
```

---

<p align="center">
  <sub>
    <strong>༺ MEPHALA ༻</strong><br/>
    <em>The Webspinner sees all. The web catches all.</em>
  </sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Crafted_by-ind4skylivey-8b5cf6?style=for-the-badge&labelColor=0d0d0d"/>
</p>

<p align="center">
  <sub>🕷️ Inspired by The Elder Scrolls V: Skyrim 🕷️</sub>
</p>
