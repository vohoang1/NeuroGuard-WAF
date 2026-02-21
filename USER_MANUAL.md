# NeuroGuard Command Center - User Manual

## System Architecture Overview
NeuroGuard Command Center consists of 5 core services running in Docker:
1. **Envoy Proxy (WAF)**: Handles incoming traffic at `http://localhost:8080`.
2. **Fluent Bit**: Ingests WAF logs and forwards them.
3. **ClickHouse**: High-performance log storage and real-time aggregations.
4. **Go API Server**: Connects to ClickHouse and provides REST endpoints.
5. **React Dashboard**: UI hosted on `http://localhost:3000`.

## 1. Starting the System
You can start the entire stack using the provided helper script:

```bash
# On Linux / Mac (or Git Bash on Windows)
chmod +x start.sh
./start.sh
```

Alternatively, you can start it manually using Docker Compose:
```bash
# Copy the environment file
cp .env.example .env

# Build the WebAssembly module
cargo build --target wasm32-wasi --release

# Start the stack
docker-compose up -d --build
```

## 2. Accessing the Dashboard
- **URL**: [http://localhost:3000](http://localhost:3000)
- **Username**: `admin`
- **Password**: `admin123`

The dashboard will automatically refresh every 10 seconds. 

## 3. Running a Test Attack
To see the SOC dashboard update in real-time, generate a simulated attack against the WAF proxy endpoint (`http://localhost:8080`).

### Simulate SQL Injection (SQLi)
```bash
curl "http://localhost:8080/products?id=1%20UNION%20SELECT%20password%20FROM%20users--"
```

### Simulate Cross-Site Scripting (XSS)
```bash
curl -X POST "http://localhost:8080/comment" \
     -H "Content-Type: application/json" \
     -d '{"body": "<script>alert(document.cookie)</script>"}'
```

After running these commands:
1. The request will return a `403 Forbidden` response created by the NeuroGuard WAF Wasm module.
2. The event is captured by Fluent Bit and pushed to ClickHouse.
3. Switch to your browser at `http://localhost:3000`.
4. Within 10 seconds you will see the **Blocked Attacks** counter increase, the pie chart update, and a new red row appear on the **Live Logs** table!

## 4. Troubleshooting
- To view the status of all containers: `docker-compose ps`
- To view Logs for the Go API: `docker-compose logs -f neuroguard-api`
- To shut down the stack completely: `docker-compose down -v`
