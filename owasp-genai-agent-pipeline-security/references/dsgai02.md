# DSGAI02: Agent Identity & Credential Exposure

### Full Attack Description

Modern AI agents are granted broad permissions to accomplish tasks—yet they operate autonomously without human oversight at each decision point. The identity model inherited from human OAuth (three-legged flows designed for users granting consent to third-party apps) is architecturally mismatched for agents:

1. **Agents as inheritors of operator scope:** An agent deployed with a user's service account token inherits all permissions that user has—database admin, API write access, billing controls. The agent then calls downstream services and tools, propagating these tokens without re-scoping to only what's needed for each task.

2. **NHI sprawl & long-lived secrets:** Organizations create per-environment (dev/prod), per-agent (sales-agent, support-agent, research-agent), and per-integration (Slack, GitHub, Salesforce) tokens with long TTLs. These accumulate in environment variables, config files, CI/CD systems, and memory with minimal tracking or rotation.

3. **No granular credential revocation:** When a task completes or an agent's role changes, the underlying OAuth token remains valid. No capability to say "revoke agent X's access to database Y, but keep API Z."

4. **Agent memory as credential store:** Agents cache tokens in session memory or persistent storage (Redis, files) for "efficiency." If an agent is compromised, its memory is an exfiltration goldmine.

### Why It Matters

- **Blast radius:** A single leaked agent token can be exploited for an extended period before detection due to long TTLs.
- **Lateral movement:** Agent with database token → agent calls downstream service → service token gets exfiltrated → attacker moves through infrastructure.
- **Silent exfiltration:** Unlike human logins, agent API calls blend in with normal traffic. Rate-limiting and geo-anomalies are weak signals.

### Implementation Guidance by Tier

#### Tier 1: Foundational Controls

**Short-Lived Tokens**
- Issue short-lived tokens for sensitive operations.
- Pair with automatic refresh (agent fetches new token before expiry) to avoid disruption.
- For stateless agents (functions, lambda), issue single-use tokens.
- Example (Kubernetes with OIDC):
  ```yaml
  apiVersion: v1
  kind: ServiceAccount
  metadata:
    name: ai-agent
  ---
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: ai-agent-task-scoped
  rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
    resourceNames: ["task-config"]  # Only specific config
  ---
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata:
    name: ai-agent-binding
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: ai-agent-task-scoped
  subjects:
  - kind: ServiceAccount
    name: ai-agent
    namespace: default
  ```

**Least-Privilege RBAC/ABAC**
- Define roles at *task granularity*, not agent granularity. Agent A can read Slack messages only when executing the "summarize-channel" task.
- Use attribute-based access control (ABAC) to bind permissions to task ID, time window, and IP range.
- Example (AWS with attribute-based policies):
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::data-bucket/*",
        "Condition": {
          "StringEquals": {
            "aws:RequestedRegion": "us-west-2",
            "aws:SourceIp": "10.0.0.0/8"
          },
          "StringLike": {
            "aws:userid": "*:ai-agent-task-*"
          },
          "DateGreaterThan": {
            "aws:CurrentTime": "[EXAMPLE_START_TIME]"
          },
          "DateLessThan": {
            "aws:CurrentTime": "[EXAMPLE_END_TIME]"
          }
        }
      }
    ]
  }
  ```

**mTLS for Agent-to-Service Communication**
- Every service the agent calls must verify the agent's identity via client certificate.
- Agent certificate pins the service's CA cert to prevent MITM.
- Example (Envoy proxy sidecar):
  ```yaml
  apiVersion: networking.istio.io/v1beta1
  kind: PeerAuthentication
  metadata:
    name: agent-mtls
  spec:
    mtls:
      mode: STRICT
  ---
  apiVersion: security.istio.io/v1beta1
  kind: AuthorizationPolicy
  metadata:
    name: agent-only
  spec:
    rules:
    - from:
      - source:
          principals: ["cluster.local/ns/default/sa/ai-agent"]
      to:
      - operation:
          methods: ["GET"]
          paths: ["/api/v1/data/*"]
  ```

**Secret Vault with RBAC**
- Store all tokens in a secrets management system (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).
- Agent requests tokens at runtime; vault logs every request.
- Revoke vault access immediately if agent is compromised.
- Example (HashiCorp Vault):
  ```bash
  # Agent authenticates with Kubernetes service account token
  vault login -method=kubernetes -role=ai-agent

  # Agent reads only the API key it needs
  vault kv get secret/api-keys/sales-db

  # Vault audit log captures:
  # [TIMESTAMP] auth_method=kubernetes entity=ai-agent action=login
  # [TIMESTAMP] entity=ai-agent action=read path=secret/api-keys/sales-db
  ```

**Immutable Audit Logs**
- Write all identity operations (token issue, refresh, revoke, API calls) to append-only logs.
- Forward logs to SIEM with alerting on anomalies (new service contacted, unusual API pattern).
- Example (Splunk query for anomaly):
  ```spl
  source=vault_audit agent_id=ai-sales-agent
  | stats count by api_endpoint
  | where count > 100 AND api_endpoint NOT IN (allowed_endpoints)
  ```

**Regular Secret Rotation**
- Schedule automatic rotation of long-lived secrets (API keys, database passwords).
- Rotate without disrupting running agents (dual-key period where old and new both work).
- Example (Python with scheduling):
  ```python
  from apscheduler.schedulers.background import BackgroundScheduler

  def rotate_agent_secrets():
      vault = hvac.Client()
      old_secret = vault.secrets.kv2.read_secret_version(
          path='ai-agent/api-key'
      )
      new_secret = generate_new_api_key()

      # Dual period: register new key with service
      register_api_key(new_secret, 'active')
      register_api_key(old_secret, 'deprecated')

      # Update vault (agents pick up new key on next refresh)
      vault.secrets.kv2.create_or_update_secret(
          path='ai-agent/api-key',
          secret_data={'key': new_secret}
      )

      # Clean up old key after grace period
      time.sleep(grace_period_seconds)  # grace period
      register_api_key(old_secret, 'revoked')

  scheduler = BackgroundScheduler()
  scheduler.add_job(rotate_agent_secrets, 'interval', days=rotation_interval)
  scheduler.start()
  ```

#### Tier 2: Advanced Controls

**Task-Scoped OAuth (Client Credentials Flow)**
- Replace three-legged OAuth with client credentials flow: agent authenticates with its own credentials, not inherited user scope.
- Issue a new token per task, with scope limited to that task's requirements.
- Example (OAuth 2.0 Client Credentials):
  ```bash
  # Agent requests token for "summarize-channel" task
  curl -X POST https://oauth.example.com/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=ai-agent-123" \
    -d "client_secret=<vault-fetched-secret>" \
    -d "scope=slack:read:channels slack:read:messages:task=summarize-channel" \
    -d "task_id=task-456" \
    -d "ttl=[SHORT_TTL_SECONDS]"  # short-lived token

  # Response:
  {
    "access_token": "eyJhbGc...",
    "token_type": "Bearer",
    "expires_in": 900,
    "scope": "slack:read:channels slack:read:messages:task=summarize-channel"
  }
  ```

**NHI Inventory & Lifecycle Tracking**
- Maintain a registry of all agent identities: name, purpose, created-date, last-rotation, services accessed.
- Automated discovery: scan environment variables, config files, CI/CD secrets, cloud provider IAM.
- Periodic review: remove agents no longer in use, audit permissions drift.
- Example (Terraform for NHI inventory):
  ```hcl
  resource "aws_iam_role" "ai_agent" {
    name = "ai-agent-${var.agent_name}"

    tags = {
      NHIType = "agent"
      AgentPurpose = var.purpose  # "sales-pipeline", "support-chat", etc.
      RotationDue = timeadd(timestamp(), rotation_interval_seconds)
      SecondaryApprover = var.secondary_approver
    }
  }

  # Automated rotation trigger
  resource "aws_cloudwatch_event_rule" "nhi_rotation" {
    schedule_expression = "rate(rotation_interval)"
  }

  resource "aws_cloudwatch_event_target" "rotate_lambda" {
    rule = aws_cloudwatch_event_rule.nhi_rotation.name
    arn = aws_lambda_function.rotate_agent_keys.arn
    input = jsonencode({
      agent_role = aws_iam_role.ai_agent.name
    })
  }
  ```

**Anomaly Detection on Identity Operations**
- Monitor for: first-time API calls, access from new IPs, time-of-day anomalies, tool combinations that never occurred before.
- Baseline: learn normal patterns over an initial observation period; then flag deviations.
- Example (Datadog/Splunk):
  ```python
  import datadog

  datadog.initialize(api_key="<key>")

  # Alert: agent accessing new service
  alert_query = """
  avg(last_5m):anomalies(avg:agent.api_calls{agent_id:ai-sales}.as_count(), 'adaptive') > 1
  """

  datadog.api.Monitor.create(
      type="metric alert",
      name="Agent accessing anomalous API endpoint",
      query=alert_query,
      options={
          "thresholds": {"critical": 1},
          "notify_no_data": True,
          "no_data_timeframe": 300
      }
  )
  ```

**Per-Agent PKI Certificates**
- Issue a unique X.509 certificate to each agent, signed by internal CA.
- Certificate includes agent ID, purpose, and valid-time window.
- Agent uses cert for mTLS to all downstream services.
- Example (OpenSSL + auto-renewal):
  ```bash
  # Create agent certificate with short TTL
  openssl req -new -keyout ai-agent-123.key -out ai-agent-123.csr \
    -subj "/CN=ai-agent-123/O=MyOrg/C=US"

  openssl x509 -req -days [CERT_TTL_DAYS] -in ai-agent-123.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out ai-agent-123.crt \
    -extfile <(printf "subjectAltName=DNS:ai-agent-123\nextendedKeyUsage=clientAuth")

  # Agent presents cert when calling API:
  curl --cert ai-agent-123.crt --key ai-agent-123.key \
    --cacert ca.crt https://api.example.com/data

  # Server verifies:
  # 1. Signature valid (CA-signed)
  # 2. CN = ai-agent-123
  # 3. Not expired
  # 4. CN is in allowed-agent list
  ```

#### Tier 3: Enterprise Controls

**Workload Identity Federation**
- Eliminate long-lived credentials: exchange workload identity (Kubernetes service account, GCP service account) for short-lived credentials at request time.
- Kubernetes → AWS: use IRSA (IAM Roles for Service Accounts) or OIDC federation.
- Example (Kubernetes + AWS IRSA):
  ```yaml
  apiVersion: v1
  kind: ServiceAccount
  metadata:
    name: ai-agent
    annotations:
      eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/ai-agent-role
  ---
  # AWS IAM role trusts Kubernetes OIDC provider
  # Terraform:
  data "tls_certificate" "eks" {
    url = aws_eks_cluster.main.identity[0].oidc[0].issuer
  }

  resource "aws_iam_openid_connect_provider" "eks" {
    client_id_list  = ["sts.amazonaws.com"]
    thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
    url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
  }

  resource "aws_iam_role" "ai_agent" {
    assume_role_policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.eks.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:default:ai-agent"
          }
        }
      }]
    })
  }
  ```
- No credential storage needed: AWS SDK automatically exchanges Kubernetes service account token for temporary AWS credentials.

**Signed Agent Requests (JWS)**
- Agent signs every API request with its private key; server verifies signature using agent's public cert.
- Prevents tampering and replay attacks.
- Example (Python with PyJWT):
  ```python
  import jwt
  import requests

  # Agent reads private key from secure location
  with open('/var/run/secrets/agent-key.pem') as f:
      private_key = f.read()

  # Agent signs request payload
  payload = {
      "agent_id": "ai-sales-123",
      "task_id": "task-456",
      "method": "GET",
      "path": "/api/v1/data",
      "timestamp": int(time.time()),
      "nonce": secrets.token_hex(16)
  }

  jws_token = jwt.encode(payload, private_key, algorithm='RS256')

  # Agent sends request with signature
  headers = {
      "Authorization": f"Bearer {jws_token}",
      "X-Request-Signature": jws_token
  }
  response = requests.get('https://api.example.com/data', headers=headers)

  # Server verifies:
  server_code = """
  import jwt

  def verify_agent_request(request):
      token = request.headers.get('X-Request-Signature')
      try:
          payload = jwt.decode(token, public_key, algorithms=['RS256'])
          # Verify timestamp is recent (within 5 min)
          # Verify nonce hasn't been seen before (replay protection)
          # Verify agent_id is in allowed list
          return True
      except jwt.InvalidSignatureError:
          return False
  ```

**Agent Memory Isolation**
- Agent's session memory (cache of tokens, conversation history) is ephemeral: cleared after task completes.
- If agent is deployed as a container, delete the container after task → no persistent attack surface.
- If agent is long-lived (service), periodically flush memory (e.g., at regular intervals or after reaching request threshold).
- Example (Python with session cleanup):
  ```python
  import weakref
  import atexit

  class AgentSession:
      def __init__(self, agent_id):
          self.agent_id = agent_id
          self.token_cache = {}
          self.conversation_history = []

          # Register cleanup on exit
          atexit.register(self.cleanup)
          weakref.finalize(self, self.cleanup)

      def cleanup(self):
          """Secure wipe of sensitive memory"""
          # Overwrite token cache
          for key in self.token_cache:
              self.token_cache[key] = 'X' * 1000  # Overwrite with junk
          self.token_cache.clear()

          # Overwrite conversation history
          for i in range(len(self.conversation_history)):
              self.conversation_history[i] = ''
          self.conversation_history.clear()

          logging.info(f"Agent {self.agent_id} session cleaned up")

  # Container-based agent
  # Docker entrypoint: run agent, then immediately exit (no persistent process)
  FROM python:3.11
  COPY agent.py /app/
  ENTRYPOINT ["python", "/app/agent.py"]
  # Task completes → container exits → memory deleted
  ```

**Continuous NHI Governance**
- Periodic scans of all systems: identify new agents, unused agents, permission drift.
- Automated removal of unused agents based on access patterns.
- Approval workflow for new agents: CTO sign-off + secondary reviewer.
- Example (Kubernetes with policy engine):
  ```yaml
  apiVersion: constraints.gatekeeper.sh/v1beta1
  kind: K8sRequiredLabels
  metadata:
    name: agent-approval-required
  spec:
    match:
      kinds:
      - apiGroups: [""]
        kinds: ["ServiceAccount"]
    parameters:
      labels: ["approvedBy", "rotationDue"]
      message: "Agent must have approvedBy and rotationDue labels"
  ```

### Related CVEs

- **CVE-2025-24357:** Agent credential leakage via environment variable exposure in logs.
- Industry findings: Anthropic, Google, OpenAI research on credential exfiltration in agentic deployments.

### Detection & Response

| Signal | Action |
|--------|--------|
| Token accessed from unusual IP or time | Invalidate token immediately; alert security team |
| Agent calls 3+ new APIs in one session | Pause agent; require human approval to resume |
| Token refresh request without prior auth | Deny; log suspicious activity |
| Token stored in plaintext in logs | Rotate token; scan logs for exfiltration |
