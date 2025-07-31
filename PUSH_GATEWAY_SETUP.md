# Complete Push Gateway Setup for Grafana

## Step 1: Download and Install Components

### Download Prometheus Push Gateway
1. Go to: https://github.com/prometheus/pushgateway/releases/latest
2. Download: `pushgateway-1.6.2.windows-amd64.tar.gz`
3. Extract to: `prometheus-pushgateway/` folder
4. You should have: `prometheus-pushgateway/pushgateway.exe`

### Download Prometheus Server
1. Go to: https://github.com/prometheus/prometheus/releases/latest  
2. Download: `prometheus-2.46.0.windows-amd64.tar.gz`
3. Extract to: `prometheus/` folder
4. You should have: `prometheus/prometheus.exe`

## Step 2: Start Services (in order)

### Terminal 1: Start Push Gateway
```bash
cd prometheus-pushgateway
pushgateway.exe
```
- Should start on: http://localhost:9091
- Leave this terminal open

### Terminal 2: Start Prometheus Server
```bash
cd prometheus
prometheus.exe --config.file=../prometheus.yml
```
- Should start on: http://localhost:9090
- Leave this terminal open

### Terminal 3: Start Flask with Push Gateway
```bash
start_flask_with_prometheus.bat
```
- Should start on: http://localhost:8000
- Will push metrics to gateway

## Step 3: Configure Grafana Data Source

1. **Open Grafana:** http://localhost:3000
2. **Go to:** Configuration → Data Sources
3. **Add/Edit Prometheus datasource:**
   - **Name:** Prometheus
   - **URL:** `http://localhost:9090` (Prometheus server, not Flask)
   - **UID:** `Prometheus`
   - **Access:** Server (default)
4. **Test & Save**

## Step 4: Verify Setup

### Check Push Gateway (http://localhost:9091)
You should see metrics like:
- `fuzzy_bn_attack_action_*`
- `binary_bn_*`

### Check Prometheus (http://localhost:9090)
1. Go to Status → Targets
2. Should show:
   - `fuzzy-bn-flask` (UP)
   - `pushgateway` (UP)

### Check Flask App (http://localhost:8000)
- `/metrics` should show Prometheus metrics
- `/status` should show push gateway enabled

## Step 5: Test in Grafana

1. **Go to Explore**
2. **Query:** `bn_*` 
3. **Should see:** All your Bayesian Network metrics

## Troubleshooting

### "Duplicated timeseries" Error
This happens when Flask tries to register the same metric twice. To fix:

1. **Stop Flask app** (Ctrl+C)
2. **Restart Flask:** `start_flask_with_prometheus.bat`
3. **Or use simple mode:** `start_flask_simple.bat`

### Push Gateway Not Receiving Metrics
1. **Check if Push Gateway is running:** http://localhost:9091
2. **Manual push test:**
   ```bash
   curl -X POST http://localhost:8000/push_metrics
   ```
3. **Check Flask logs** for push errors

### Grafana Can't Connect
1. **Verify Prometheus URL:** Should be `http://localhost:9090` (not 8000)
2. **Check Prometheus targets:** http://localhost:9090/targets
3. **Verify UID is exactly:** `Prometheus`

## Architecture Overview

```
Flask App (8000) → Push Gateway (9091) → Prometheus (9090) → Grafana (3000)
```

## Alternative: Direct Scraping (Simpler)

If push gateway is causing issues, use direct scraping:

1. **Start Flask simply:**
   ```bash
   start_flask_simple.bat
   ```

2. **Configure Grafana datasource:**
   - URL: `http://localhost:8000` (Flask directly)
   - UID: `Prometheus`

This skips the push gateway entirely and works just as well for your use case.

## Recommendation

For your Bayesian Network dashboard, **direct scraping is actually better** because:
- ✅ Simpler setup (no additional services)
- ✅ Real-time updates (Grafana scrapes every 5 seconds)
- ✅ No "duplicated timeseries" issues
- ✅ Fewer moving parts to troubleshoot

Push gateway is mainly useful for:
- Batch jobs that can't be scraped
- Services behind firewalls
- Short-lived processes

Your Flask app is a long-running service that can be scraped directly, so push gateway adds unnecessary complexity.
