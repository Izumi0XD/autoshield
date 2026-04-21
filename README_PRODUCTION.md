# AutoShield Production Setup

## Overview
AutoShield is now configured as a production-grade web security system that actively protects a connected website by monitoring traffic, detecting attacks, and automatically blocking malicious IPs.

## Architecture
- **Nginx Proxy**: Reverse proxy that forwards traffic to the backend website and logs requests.
- **Log Agent**: Tails Nginx access logs, detects attacks using rule-based patterns, and sends events to the API.
- **API Backend**: FastAPI server that receives events, stores them in PostgreSQL, and handles blocking via iptables.
- **Dashboard**: Real-time React dashboard showing live events and stats.
- **Database**: PostgreSQL for persistent storage.

## Components
- Nginx (port 80) - Traffic proxy
- AutoShield API (port 8503) - Backend
- Dashboard (port 3000) - Frontend
- PostgreSQL - Database
- Backend Website (port 8080) - Protected site

## Deployment

### Prerequisites
- Docker and Docker Compose
- At least 4GB RAM

### Quick Start
1. Clone/update the repository
2. Run: `docker-compose up --build`
3. Access dashboard at http://localhost:3000
4. Test protection by sending malicious requests to http://localhost

### Configuration
- API key: `as_demo_key_change_in_production` (change in production)
- Database: PostgreSQL at db:5432
- Logs: Mounted volumes for persistence

## Testing Protection
1. Normal request: `curl "http://localhost/search?q=test"`
2. SQL Injection: `curl "http://localhost/search?q=' OR 1=1 --"`
3. XSS: `curl "http://localhost/search?q=<script>alert(1)</script>"`
4. Check dashboard for detections and blocks
5. Check blocked IPs: `docker exec autoshield-api iptables -L`

## Key Features
- Real-time attack detection (SQLi, XSS, LFI, CMDi)
- Automatic IP blocking via iptables
- Live dashboard with WebSocket updates
- PostgreSQL persistence
- DDoS protection with rate limiting
- Geo-blocking capabilities

## Security Notes
- Change default API keys
- Use HTTPS in production
- Monitor logs regularly
- Backup database

## Troubleshooting
- Check logs: `docker-compose logs api`
- Health check: `curl http://localhost:8503/health`
- Database: `docker exec -it db psql -U user -d autoshield`