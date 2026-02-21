#!/bin/bash
set -e

echo "========================================="
echo " Starting NeuroGuard WAF Command Center  "
echo "========================================="

# Check if .env exists, if not, copy from .env.example
if [ ! -f .env ]; then
    echo "[!] .env file not found. Creating from .env.example..."
    cp .env.example .env
fi

echo "[*] Building Rust WASM plugin..."
cargo build --target wasm32-wasi --release

echo "[*] Tearing down previous containers (if any)..."
docker-compose down -v

echo "[*] Building and starting Docker Compose stack..."
docker-compose up -d --build

echo "========================================="
echo " Deployment Successful! "
echo "========================================="
echo "Access the Dashboard: http://localhost:3000"
echo "WAF Proxy Endpoint:   http://localhost:8080"
echo "Metrics / Admin:      http://localhost:9901"
echo ""
echo "Use 'docker-compose logs -f' to view logs."
