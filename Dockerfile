FROM python:3.11-slim

# System deps for Scapy + iptables + PostgreSQL
RUN apt-get update && apt-get install -y \
    iptables \
    libpcap-dev \
    gcc \
    curl \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# API port
EXPOSE 8503

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8503/health || exit 1

# Run API
CMD ["python", "api_layer.py"]
