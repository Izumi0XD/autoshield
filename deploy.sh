#!/bin/bash
# ============================================================
# AutoShield — VPS Deploy Script
# Tested on Ubuntu 22.04 / Debian 12
# Run as root on a fresh VPS (DigitalOcean, Linode, Hetzner)
# Usage: bash deploy.sh [your-domain.com]
# ============================================================
set -e

DOMAIN="${1:-}"
API_KEY="as_$(openssl rand -hex 24)"
REPO_DIR="/opt/autoshield"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║  AutoShield VPS Deploy               ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ─── 1. System deps ───────────────────────────────────────────
echo "[1/7] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    docker.io \
    docker-compose \
    curl \
    git \
    ufw \
    openssl \
    certbot

systemctl enable --now docker

# ─── 2. Firewall ──────────────────────────────────────────────
echo "[2/7] Configuring firewall..."
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3000/tcp
ufw --force enable

# ─── 3. Copy project files ────────────────────────────────────
echo "[3/7] Setting up project directory..."
mkdir -p "$REPO_DIR"
cp -r . "$REPO_DIR/"
cd "$REPO_DIR"

# ─── 4. Write .env ────────────────────────────────────────────
echo "[4/7] Writing .env..."
cat > .env << EOF
AUTOSHIELD_API_KEY=${API_KEY}
POSTGRES_PASSWORD=$(openssl rand -hex 16)
EOF

echo ""
echo "  ✅ API Key: ${API_KEY}"
echo "  Save this — you'll need it for the dashboard login."
echo ""

# ─── 5. SSL (optional, needs domain) ─────────────────────────
if [ -n "$DOMAIN" ]; then
    echo "[5/7] Getting SSL certificate for $DOMAIN ..."
    certbot certonly --standalone --non-interactive --agree-tos \
        --email "admin@${DOMAIN}" -d "$DOMAIN" || echo "  ⚠️  SSL failed — continuing with HTTP"
    
    # Patch nginx.conf to use HTTPS if cert obtained
    if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
        cat >> nginx.conf << NGINX_PATCH
# SSL handled by certbot — mount certs and add HTTPS server block manually
NGINX_PATCH
        echo "  ✅ SSL certs at /etc/letsencrypt/live/${DOMAIN}/"
    fi
else
    echo "[5/7] No domain provided — skipping SSL (HTTP only)"
fi

# ─── 6. Build + start ─────────────────────────────────────────
echo "[6/7] Building and starting containers..."
docker-compose pull --quiet db 2>/dev/null || true
docker-compose up --build -d

echo ""
echo "  Waiting for containers to start..."
sleep 10

# Health check
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8503/health || echo "000")
if [ "$HTTP_STATUS" = "200" ]; then
    echo "  ✅ API healthy"
else
    echo "  ⚠️  API not responding yet (status $HTTP_STATUS) — check: docker-compose logs api"
fi

# ─── 7. Summary ───────────────────────────────────────────────
echo ""
echo "[7/7] Deploy complete!"
echo ""
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
echo "╔══════════════════════════════════════════════════════╗"
echo "║  AutoShield is LIVE                                  ║"
echo "╠══════════════════════════════════════════════════════╣"
if [ -n "$DOMAIN" ]; then
echo "║  Dashboard:    http://${DOMAIN}:3000                 ║"
echo "║  Protected:    http://${DOMAIN}                      ║"
echo "║  API:          http://${DOMAIN}:8503/health          ║"
else
echo "║  Dashboard:    http://${SERVER_IP}:3000              ║"
echo "║  Protected:    http://${SERVER_IP}                   ║"
echo "║  API:          http://${SERVER_IP}:8503/health       ║"
fi
echo "║  API Key:      ${API_KEY}  ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Test attacks:                                       ║"
echo "║    curl \"http://${SERVER_IP}/search?q=' OR 1=1 --\"  ║"
echo "║    curl \"http://${SERVER_IP}/x?q=<script>alert(1)\" ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Manage:                                             ║"
echo "║    docker-compose logs -f api                        ║"
echo "║    docker-compose restart api                        ║"
echo "║    docker exec autoshield-api iptables -L            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
