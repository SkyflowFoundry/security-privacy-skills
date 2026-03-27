# DSGAI05: Data Integrity & Validation Failures

### Full Attack Description

Data pipelines often trust input format without validating content semantically. Three attack vectors:

1. **Schema/syntax validation only:** A CSV file parses syntactically (all columns present, correct separators) but contains semantically malicious data. Example: label-flip attack (change "benign" to "malicious" in training data). Or: import path with a symlink (`/tmp/data/training.csv` → symlink to `/etc/passwd`), which passes basic checks but reads the wrong file.

2. **Malformed structured data:** JSON, Parquet, or Avro files with unusual but valid structures. Example: Parquet file with 1B rows instead of expected 1M (denial-of-service via out-of-memory).

3. **Path traversal at import:** Snapshot deserialization vulnerabilities (Qdrant CVE-2024-3584). An attacker crafts a specially formatted import file that, when deserialized, writes arbitrary files outside the intended directory.

### Why It Matters

- **Silent corruption:** Data passes validation, gets used in training, and silently corrupts the model. No alerts, no failures.
- **Downstream trust:** Once data is ingested and used, it spreads to all downstream models, reports, and decisions.
- **Regulatory risk:** If you can't prove data integrity, you can't prove compliance (GDPR, HIPAA, SOX).

### Implementation Guidance by Tier

#### Tier 1: Foundational Controls

**Strict Schema Enforcement**
- Validate against formal schemas: JSON Schema, Apache Avro, Parquet format.
- Reject any row/file that doesn't match exactly.
- Example (JSON Schema):
  ```json
  {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
      "customer_id": {
        "type": "integer",
        "minimum": 1
      },
      "transaction_amount": {
        "type": "number",
        "minimum": 0,
        "maximum": 1000000
      },
      "status": {
        "type": "string",
        "enum": ["approved", "rejected", "pending"]
      }
    },
    "required": ["customer_id", "transaction_amount", "status"],
    "additionalProperties": false
  }
  ```
  Python validation:
  ```python
  import jsonschema

  with open('schema.json') as f:
      schema = json.load(f)

  def validate_record(record):
      try:
          jsonschema.validate(record, schema)
          return True
      except jsonschema.ValidationError as e:
          logging.error(f"Schema validation failed: {e}")
          return False

  # Reject any invalid record
  for record in input_data:
      if not validate_record(record):
          raise ValueError(f"Invalid record: {record}")
  ```

**Semantic Validation**
- Beyond schema, validate business logic: ranges, relationships, impossibilities.
- Example:
  ```python
  def semantic_validation(record):
      # Schema check passed; now check semantics

      # Sanity check: transaction amount
      if record['transaction_amount'] > 1000000:
          raise ValueError("Transaction suspiciously large")

      # Relationship check: if status is 'approved', approver_id must be set
      if record['status'] == 'approved' and not record.get('approver_id'):
          raise ValueError("Approved transaction missing approver_id")

      # Impossibility check: approval timestamp cannot be before creation
      if record['approved_at'] < record['created_at']:
          raise ValueError("Approved before created")

      return True
  ```

**Sanitize Filenames, Refuse Symlinks**
- Import paths must be validated: no `..`, no absolute paths, no symlinks.
- Example (Python):
  ```python
  import os
  from pathlib import Path

  def safe_import_path(user_provided_path, base_dir):
      # Resolve to absolute path
      full_path = (Path(base_dir) / user_provided_path).resolve()

      # Ensure path is within base_dir (prevents ../../../etc/passwd)
      if not str(full_path).startswith(str(Path(base_dir).resolve())):
          raise ValueError("Path traversal detected")

      # Refuse if it's a symlink
      if full_path.is_symlink():
          raise ValueError("Symlinks not allowed")

      # Refuse if it's a directory (prevent reading directories)
      if full_path.is_dir():
          raise ValueError("Directories not allowed, only files")

      return full_path

  # Usage:
  safe_path = safe_import_path('data/training.csv', '/var/data')
  df = pd.read_csv(safe_path)
  ```

**Cryptographic Integrity Verification**
- Require a SHA-256 hash for every imported file.
- Recompute hash on import and compare.
- Example:
  ```python
  import hashlib

  # At export time, compute and store hash
  with open('training_data.csv', 'rb') as f:
      file_hash = hashlib.sha256(f.read()).hexdigest()

  metadata = {
      'file': 'training_data.csv',
      'hash': file_hash,
      'created_by': 'pipeline-123',
      'created_at': '[CREATION_TIMESTAMP]'
  }

  # At import time, verify hash
  def import_with_integrity_check(filepath, expected_hash):
      with open(filepath, 'rb') as f:
          actual_hash = hashlib.sha256(f.read()).hexdigest()

      if actual_hash != expected_hash:
          raise ValueError(f"Hash mismatch: expected {expected_hash}, got {actual_hash}")

      return pd.read_csv(filepath)
  ```

**Immutable Audit Trail**
- Log every import: who imported, when, file hash, schema validation result, row count.
- Write logs to append-only storage (can't be modified).
- Example (CloudWatch Logs + immutable S3 bucket):
  ```python
  import boto3
  import json
  from datetime import datetime

  logs_client = boto3.client('logs')

  def log_import(file_path, file_hash, row_count, validation_passed):
      log_entry = {
          'timestamp': datetime.utcnow().isoformat(),
          'file': file_path,
          'hash': file_hash,
          'row_count': row_count,
          'validation': 'passed' if validation_passed else 'failed',
          'user': os.getenv('USER'),
          'pipeline_id': os.getenv('PIPELINE_ID')
      }

      logs_client.put_log_events(
          logGroupName='/aws/ai-pipelines/imports',
          logStreamName='data-imports',
          logEvents=[
              {
                  'message': json.dumps(log_entry),
                  'timestamp': int(time.time() * 1000)
              }
          ]
      )
  ```

#### Tier 2: Advanced Controls

**Hardened Import Paths (Chroot / Container Jail)**
- Run import operations in a chroot jail or container with minimal privileges.
- Import can only access designated directory; can't escape to rest of filesystem.
- Example (Docker container for import):
  ```dockerfile
  FROM python:3.11-slim

  COPY import_script.py /app/

  # Non-root user
  RUN useradd -m importer && chown -R importer /app
  USER importer

  # Import data only from /data (mounted volume)
  VOLUME ["/data"]

  ENTRYPOINT ["python", "/app/import_script.py", "/data/input.csv"]
  ```
  Run with minimal mounts:
  ```bash
  docker run --rm \
    -v /host/data:/data:ro \
    -v /host/output:/output:rw \
    --read-only \
    --cap-drop=ALL \
    my-importer
  ```

**SELinux/AppArmor Confinement**
- Use OS-level mandatory access control to restrict what the import process can access.
- Example (AppArmor):
  ```
  #include <tunables/global>

  /usr/local/bin/import_data {
    #include <abstractions/base>
    #include <abstractions/python>

    /var/data/imports/ rw,
    /var/data/imports/** rw,

    deny /etc/** rwx,
    deny /home/** rwx,
    deny /root/** rwx,
    deny /tmp/** rwx,
  }
  ```

**Read-Only Mount for Input**
- Mount input data as read-only; import script can read but not modify.
- Prevents accidental or malicious data mutation during import.
- Example (Linux mount):
  ```bash
  mount -o ro /mnt/raw_data /mnt/input

  # Script tries to write to /mnt/input → permission denied
  echo "modified" > /mnt/input/data.csv
  # bash: /mnt/input/data.csv: Read-only file system
  ```

**Ingestion Anomaly Detection**
- Monitor imports for unusual patterns: unexpected file sizes, row counts, data distributions.
- Example (Prometheus alerting):
  ```python
  from prometheus_client import Gauge

  import_file_size = Gauge('import_file_size_bytes', 'Size of imported file')
  import_row_count = Gauge('import_row_count', 'Number of rows imported')

  def import_with_monitoring(filepath):
      file_size = os.path.getsize(filepath)
      import_file_size.set(file_size)

      df = pd.read_csv(filepath)
      import_row_count.set(len(df))

      # Alert if size/count differs from baseline by > 2 sigma
      if file_size > baseline_size + 2*std_dev:
          alert("Imported file unusually large")
  ```

#### Tier 3: Enterprise Controls

**Semantic Validation (Statistical Bounds, Relationship Checks)**
- Validate data distributions statistically: column means, correlations, outliers.
- Example (statistical validation):
  ```python
  import scipy.stats

  def statistical_validation(df_new, df_baseline):
      """
      Check if new data has similar distributions to baseline.
      """
      for col in df_new.columns:
          if col not in df_baseline.columns:
              raise ValueError(f"New column {col} not in baseline")

          # KS test: are distributions similar?
          ks_stat, p_value = scipy.stats.ks_2samp(df_new[col], df_baseline[col])

          if p_value < 0.01:  # Statistically significant difference
              logging.warning(f"Column {col} distribution differs from baseline (p={p_value})")

          # Outlier detection
          Q1 = df_baseline[col].quantile(0.25)
          Q3 = df_baseline[col].quantile(0.75)
          IQR = Q3 - Q1

          outliers = df_new[(df_new[col] < Q1 - 1.5*IQR) | (df_new[col] > Q3 + 1.5*IQR)]

          if len(outliers) > len(df_new) * 0.05:  # > 5% outliers
              logging.warning(f"Column {col} has {len(outliers)} outliers")
  ```

**Defense-in-Depth**
- Combine: non-root process, capability dropping, SELinux, read-only filesystems.
- Example (systemd service):
  ```ini
  [Service]
  Type=oneshot
  User=importer
  Group=importer

  # Capabilities: drop all except NET_BIND_SERVICE (if needed)
  AmbientCapabilities=
  CapabilityBoundingSet=~CAP_SETFCAP CAP_SETPCAP CAP_SYS_ADMIN CAP_SYS_PTRACE

  # Filesystem
  PrivateTmp=yes
  ProtectSystem=strict
  ReadWritePaths=/var/data/imports /var/data/output
  NoNewPrivileges=yes

  # Networking
  RestrictNamespaces=yes
  RestrictRealtime=yes

  ExecStart=/usr/local/bin/import_data
  ```

**Runtime Data Validation at Use Time**
- Even after import, validate data before training or inference.
- Example:
  ```python
  def train_with_runtime_validation(model, df):
      # Pre-training validation
      if len(df) < MIN_ROWS:
          raise ValueError(f"Dataset too small: {len(df)} rows < {MIN_ROWS}")

      # Mid-training: periodically check data sanity
      for epoch in range(num_epochs):
          model.train()
          for batch in dataloader:
              # Check batch for poisoning signals
              if detect_poisoning(batch):
                  raise ValueError("Poison detected in batch")

              loss = model(batch)
              loss.backward()
              optimizer.step()
  ```

### Related CVEs

- **CVE-2024-3584:** Qdrant snapshot deserialization RCE. Attacker crafts a snapshot file that, when loaded, executes arbitrary code via unsafe pickle deserialization.
  ```python
  # Vulnerable Qdrant code (simplified):
  import pickle

  def load_snapshot(snapshot_file):
      with open(snapshot_file, 'rb') as f:
          data = pickle.load(f)  # RCE if snapshot_file is malicious
      return data

  # Fix: use safe deserialization
  import json
  def load_snapshot(snapshot_file):
      with open(snapshot_file, 'r') as f:
          data = json.load(f)  # JSON is safe (no code execution)
      return data
  ```

- **CVE-2024-3829:** Qdrant path traversal via symlink in import.

### Detection & Response

| Signal | Action |
|--------|--------|
| Row count > 2 sigma from baseline | Flag for review; may proceed with caution |
| Hash mismatch on re-import | Quarantine file; investigate source |
| Schema validation fails | Reject import; require fix |
| Semantic check fails (label flip, etc.) | Quarantine batch; alert security |
