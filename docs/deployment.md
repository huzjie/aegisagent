# AegisAgent Deployment Guide

This guide covers deployment options for AegisAgent, including Docker, Kubernetes, and bare-metal installations.

## Prerequisites

- **Python 3.10+** (for bare-metal deployment)
- **Docker 24.0+** (for containerized deployment)
- **Kubernetes 1.28+** (for orchestration)
- Minimum 2GB RAM, 2 CPU cores
- Network access to LLM providers (OpenAI, Anthropic, etc.)

## Docker Deployment

### Single Container

The simplest deployment method:

```bash
# Build the image
docker build -t aegisagent:latest .

# Run the container
docker run -d \
  --name aegis-server \
  -p 8901:8901 \
  -p 8902:8902 \
  -v aegis-config:/etc/aegis \
  -v aegis-data:/var/lib/aegis \
  -e AEGIS_LOG_LEVEL=info \
  aegisagent:latest
```

### Docker Compose

For multi-service deployments:

```bash
# Start all services
docker compose up -d

# Start with optional MCP server
docker compose --profile mcp up -d

# Start with example agent
docker compose --profile examples up -d

# View logs
docker compose logs -f aegis-server

# Stop all services
docker compose down
```

**Services**:
- `aegis-server`: Main gateway (ports 8901, 8902)
- `example-agent`: Demo agent (profile: examples)
- `mcp-server`: MCP security proxy (profile: mcp, port 8910)

### Docker Image Configuration

**Environment Variables**:

| Variable | Default | Description |
|---|---|---|
| `AEGIS_LOG_LEVEL` | `info` | Logging level (debug, info, warning, error) |
| `AEGIS_POLICY_DIR` | `/etc/aegis/policy` | Policy files directory |
| `AEGIS_AUDIT_BACKEND` | `file` | Audit log backend (file, postgresql) |
| `AEGIS_AUDIT_PATH` | `/var/lib/aegis/audit.jsonl` | Audit log file path |
| `AEGIS_GATEWAY_HOST` | `0.0.0.0` | Gateway bind address |
| `AEGIS_GATEWAY_PORT` | `8901` | Gateway HTTP port |
| `AEGIS_WS_PORT` | `8902` | WebSocket port for approvals |

**Volumes**:
- `/etc/aegis`: Configuration files
- `/var/lib/aegis`: Persistent data (audit logs, keys)
- `/var/log/aegis`: Log files (optional)

## Kubernetes Deployment

### Manifest Files

Deploy to Kubernetes using the provided manifests:

```bash
# Apply all manifests
kubectl apply -f deploy/k8s/

# Or apply individually
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/secret.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/ingress.yaml
```

### Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: aegisagent
```

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aegis-config
  namespace: aegisagent
data:
  config.yaml: |
    gateway:
      host: 0.0.0.0
      port: 8901
    policy:
      dir: /etc/aegis/policy
    audit:
      backend: postgresql
      dsn: postgresql://aegis:${DB_PASSWORD}@postgres:5432/aegis
```

### Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: aegis-secrets
  namespace: aegisagent
type: Opaque
stringData:
  db-password: "changeme"
  api-key: "your-api-key-here"
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aegis-server
  namespace: aegisagent
spec:
  replicas: 3
  selector:
    matchLabels:
      app: aegis-server
  template:
    metadata:
      labels:
        app: aegis-server
    spec:
      containers:
      - name: aegis
        image: aegisagent:latest
        ports:
        - containerPort: 8901
        - containerPort: 8902
        env:
        - name: AEGIS_LOG_LEVEL
          value: "info"
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8901
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8901
          initialDelaySeconds: 5
          periodSeconds: 10
        volumeMounts:
        - name: config
          mountPath: /etc/aegis
        - name: data
          mountPath: /var/lib/aegis
      volumes:
      - name: config
        configMap:
          name: aegis-config
      - name: data
        persistentVolumeClaim:
          claimName: aegis-data
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: aegis-server
  namespace: aegisagent
spec:
  selector:
    app: aegis-server
  ports:
  - name: http
    port: 8901
    targetPort: 8901
  - name: ws
    port: 8902
    targetPort: 8902
  type: ClusterIP
```

### Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: aegis-ingress
  namespace: aegisagent
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  rules:
  - host: aegis.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: aegis-server
            port:
              number: 8901
  tls:
  - hosts:
    - aegis.example.com
    secretName: aegis-tls
```

### Horizontal Pod Autoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: aegis-hpa
  namespace: aegisagent
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: aegis-server
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Bare-Metal Deployment

### System Requirements

- **OS**: Ubuntu 22.04+, Debian 12+, RHEL 9+, or macOS 14+
- **Python**: 3.10 or higher
- **Memory**: 2GB minimum, 4GB recommended
- **Disk**: 1GB for application + storage for audit logs

### Installation

```bash
# Create dedicated user
sudo useradd -r -s /sbin/nologin aegis

# Install AegisAgent
sudo pip install aegisagent[all]

# Create directories
sudo mkdir -p /etc/aegis /var/lib/aegis /var/log/aegis
sudo chown aegis:aegis /etc/aegis /var/lib/aegis /var/log/aegis

# Initialize configuration
sudo -u aegis aegis init --config-dir /etc/aegis
```

### Systemd Service

Create `/etc/systemd/system/aegis.service`:

```ini
[Unit]
Description=AegisAgent Security Gateway
After=network.target

[Service]
Type=simple
User=aegis
Group=aegis
ExecStart=/usr/local/bin/aegis serve --host 0.0.0.0 --port 8901
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable aegis
sudo systemctl start aegis

# Check status
sudo systemctl status aegis
```

### Nginx Reverse Proxy

```nginx
upstream aegis_backend {
    server 127.0.0.1:8901;
}

server {
    listen 443 ssl http2;
    server_name aegis.example.com;

    ssl_certificate /etc/letsencrypt/live/aegis.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/aegis.example.com/privkey.pem;

    location / {
        proxy_pass http://aegis_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws {
        proxy_pass http://aegis_backend:8902;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## Production Checklist

### Security

- [ ] Enable TLS for all endpoints
- [ ] Rotate API keys and attestation signing keys
- [ ] Configure firewall rules (allow only necessary ports)
- [ ] Enable audit log export to SIEM
- [ ] Run `aegis redteam run` to validate security
- [ ] Review and harden policy configurations

### Performance

- [ ] Configure appropriate resource limits
- [ ] Enable horizontal scaling (K8s HPA or load balancer)
- [ ] Set up monitoring (Prometheus, Grafana)
- [ ] Configure alerting for critical events

### Reliability

- [ ] Set up health checks and auto-restart
- [ ] Configure backup for audit logs and configuration
- [ ] Test disaster recovery procedures
- [ ] Document runbooks for common issues

### Compliance

- [ ] Enable tamper-evident audit logs
- [ ] Configure data retention policies
- [ ] Document access control procedures
- [ ] Schedule regular security reviews

## Monitoring

### Prometheus Metrics

AegisAgent exposes metrics on `http://localhost:8901/metrics`:

- `aegis_tool_calls_total`: Total tool calls processed
- `aegis_policy_evaluations_total`: Policy evaluation count
- `aegis_detection_alerts_total`: Detection alerts triggered
- `aegis_approval_requests_total`: HITL approval requests
- `aegis_evaluation_duration_seconds`: Evaluation latency

### Grafana Dashboard

Import the provided dashboard from `deploy/grafana/aegis-dashboard.json`.

## Troubleshooting

### Common Issues

**Gateway won't start**:
- Check logs: `docker logs aegis-server` or `journalctl -u aegis`
- Verify configuration: `aegis policy validate`
- Ensure ports 8901/8902 are not in use

**High latency**:
- Check database connection (if using PostgreSQL audit backend)
- Review policy complexity (simplify if needed)
- Enable performance profiling: `AEGIS_PROFILE=1`

**Policy not taking effect**:
- Reload policies: `aegis policy reload`
- Check policy syntax: `aegis policy validate`
- Verify policy priority order

## Support

For deployment issues:
- GitHub Discussions: https://github.com/huzjie/aegisagent/discussions
- Security issues: security@aegisagent.dev
