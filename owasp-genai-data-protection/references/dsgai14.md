# DSGAI14 — Excessive Telemetry & Monitoring Leakage

### Attack Mechanics

Debug logs, traces, and metrics capture full prompts, responses, tool outputs, and credentials. Observability platforms (Datadog, New Relic, CloudWatch) become exfiltration targets. Breaches of logging/monitoring services expose all captured data.

**Example**: A developer logs the full API response to debug an issue: `logger.info(f"Response: {response_object}")`. Response contains a customer's medical history. Log is shipped to SaaS logging service. Attacker breaches logging service and accesses the log.

### CVE & Incident Examples

- **Datadog Logging Breach**: Multiple Datadog customers leaked API keys, credentials, and PII in logs stored on Datadog's platform.
- **Sumo Logic Malicious Access**: Attackers accessed Sumo Logic's observability platform, viewing logs from customers (potentially containing sensitive data).
- **GitHub Actions Logs Leakage**: Developers accidentally committed logs containing tokens and secrets to CI/CD logs.

### Tier 1: Essential Mitigations

#### 1.1 Least-Logging Principle
**Implement**:
- Log function entry/exit and errors, not payloads.
- Example:
  ```
  ❌ logger.info(f"Query: {query_text}, Response: {response}")
  ✅ logger.info(f"Query completed in 250ms")
  ```
- If you must log data, redact PII first.
  ```
  ✅ redacted_query = redact_pii(query_text)
     logger.info(f"Query: {redacted_query}")
  ```

#### 1.2 PII Scanning on Logs
**Implement**:
- Automated scanning detects PII patterns in log output (before shipping to observability backend).
- Regex detectors: SSN, email, phone, credit card.
- ML-based detectors: For context-specific PII (e.g., customer names in logs).

**Tools**:
- `CloudWatch Logs Insights` (AWS): Runs queries to find potential PII patterns.
- `Splunk` with PII add-on: Automatic redaction of sensitive data.
- Custom regex scanning (open-source):
  ```python
  import re

  PII_PATTERNS = {
      "SSN": r"\d{3}-\d{2}-\d{4}",
      "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
      "Credit Card": r"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}",
      "Phone": r"(\d{3}[-.\s]?)?\d{3}[-.\s]?\d{4}",
  }

  def redact_pii(text):
      for pii_type, pattern in PII_PATTERNS.items():
          text = re.sub(pattern, f"[REDACTED_{pii_type}]", text)
      return text

  log_line = "SSN: 123-45-6789, Email: john@example.com"
  print(redact_pii(log_line))
  # Output: "SSN: [REDACTED_SSN], Email: [REDACTED_Email]"
  ```

#### 1.3 Retention Alignment with Data Lifecycle
**Implement**:
- Logs should not outlive source data.
- If user data is purged from the main system, related logs must also be purged.
- Example:
  ```
  User data deletion (GDPR request):
    1. Delete customer record from database
    2. Delete all logs mentioning that customer
    3. Delete all observability data (traces, metrics) related to that user
    4. Purge from backups
  ```

**Implementation**:
```python
def delete_user_data(user_id, tenant_id):
    # Delete from database
    db.execute(f"DELETE FROM users WHERE user_id = ?", (user_id,))

    # Delete from logs
    logs.delete_query(f"user_id={user_id}")

    # Delete from observability
    datadog_client.delete_metrics(
        filter={"tags": [f"user_id:{user_id}", f"tenant_id:{tenant_id}"]}
    )

    # Delete from backups
    backup_service.purge_snapshots_mentioning(user_id)

    # Audit trail
    audit_log.record("USER_DATA_DELETION", user_id, tenant_id, timestamp=now())
```

#### 1.4 Third-Party Vendor Controls
**Implement**:
- **Data Processing Agreements (DPA)**: Require vendors to sign agreements specifying:
  - No data retention beyond processing.
  - Encryption in transit (TLS) and at rest (AES-256).
  - No training on log data.
  - Subprocessor controls (vendor cannot delegate to third parties without approval).

- **Verification**: Audit vendors' security practices.
  - Request SOC 2 Type II reports.
  - Verify encryption is enabled.
  - Test that data is purged after retention period.

**Contract Language**:
> "Vendor agrees to: (1) Process log data only for the purpose of providing logging services. (2) Encrypt all data in transit (TLS 1.2+) and at rest (AES-256). (3) Purge log data according to defined retention policies unless Customer requests retention. (4) Not train on, share, or sell log data. (5) Notify Customer promptly upon any breach."

---

### Tier 2: Hardened Controls

#### 2.1 Tiered Debug Sessions with Expiry
**Implement**:
- Enable verbose logging only during troubleshooting windows.
- Require re-authentication to extend.
- Higher verbosity = shorter TTL.

**Example**:
```python
class DebugSession:
    DEBUG_LEVELS = {
        "info": {"ttl": "standard", "logs": "entry/exit, errors"},
        "debug": {"ttl": "shorter", "logs": "all above + payloads (redacted)"},
        "verbose": {"ttl": "minimal", "logs": "all above + unredacted data (DANGEROUS)"},
    }

    def enable_debug(self, user_id, level="debug"):
        ttl = self.DEBUG_LEVELS[level]["ttl"]
        session_id = secrets.token_urlsafe(32)

        self.redis.setex(
            f"debug_session:{session_id}",
            ttl,
            json.dumps({"user_id": user_id, "level": level})
        )

        self.audit_log.record("DEBUG_SESSION_STARTED", user_id, level, ttl)
        return session_id

    def disable_debug(self, session_id):
        self.redis.delete(f"debug_session:{session_id}")
        self.audit_log.record("DEBUG_SESSION_ENDED", session_id)
```

#### 2.2 Hardened Observability RBAC
**Implement**:
- Restrict who can view logs by role.
- Engineering team can view app logs (no customer data).
- Security team can view audit logs (with sensitive data redacted).
- Use mTLS between services and logging backend.

**Access Policy**:
```
Role: Engineer
  Can view: app_logs, error_logs
  Cannot view: audit_logs, debug_logs, performance_traces (if they contain PII)

Role: Security
  Can view: audit_logs (unredacted), breach_detection_alerts
  Cannot view: debug_logs (too verbose), raw_payloads

Role: Admin
  Can view: everything (with approval + audit trail)

Role: Customer Support
  Can view: customer_specific_logs (only their customer's data)
```

**Implementation** (using Datadog RBAC):
```python
# Restrict access to logs by role
datadog_client.update_log_access_policy({
    "name": "customer_pii_logs",
    "filter": "source:chat_api",  // Logs that might contain PII
    "restricted_roles": ["engineer"],  // Engineers cannot view
    "allowed_roles": ["security", "admin"],  // Security and admins can view
    "requires_approval": True,  // Approval required even for allowed roles
})
```

#### 2.3 Automated PII Scanning + Alerting
**Implement**:
- Continuous scanning of logs for PII.
- Alert security team on high-confidence hits.
- Auto-redact or quarantine flagged logs.

**Example (Splunk)**:
```
# Search for PII patterns in logs
index=main source=*api* (SSN OR creditcard OR api_key OR password)
| stats count by host, source_ip
| where count > 5
| alert email=security@company.com

# Auto-redact matching logs
|  eval _raw=replace(_raw, "\d{3}-\d{2}-\d{4}", "[REDACTED_SSN]")
```

---

### Tier 3: Defense-in-Depth

#### 3.1 Internal-Only Observability
**Implement**:
- For sensitive data paths, use on-premises logging (not third-party SaaS).
- Maintain strict access controls: only security team can access.
- Encrypt logs at rest and in transit.

**Deployment**:
```
On-Premises Logging Stack:
  ├── Application (logs events)
  ├── Syslog Collector (aggregates logs, applies redaction)
  ├── Log Storage (encrypted, on-premises)
  ├── Query Interface (access-controlled, audit-logged)
  └── Retention Manager (automated purge)

External SaaS (used only for non-sensitive paths):
  └── Datadog (general metrics, non-PII traces)
```

#### 3.2 Log-Level Isolation
**Implement**:
- Different retention/access policies for different log levels.
  - Info: standard retention, engineers can view.
  - Warn: extended retention, security team can view.
  - Error: extended retention, on-call team can view.
  - Debug: short retention, only during active debugging session.
  - Trace: minimal retention, discarded automatically.
