# DSGAI19 — Human-in-the-Loop & Labeler Overexposure

### Attack Mechanics

RLHF and labeling pipelines expose raw prompts and model completions to human labelers at massive scale. Labelers see unredacted user data, secrets, and PII. Vendor and crowd-platform security controls are often weak. Labelers (contractors, crowd-source workers) may copy data to USB drives or share with third parties.

**Example**: You're training a reward model for customer support. You send 100K prompt-completion pairs to a labeling vendor for quality scoring. Each pair contains unredacted customer queries and support responses. A labeler's account is breached, and all 100K pairs are exfiltrated.

### CVE & Incident Examples

- **OpenAI Contractor Data Breach (2023)**: OpenAI's RLHF labeling vendor was breached; sensitive user data from conversations was exposed.
- **Scale AI Data Leakage**: Scale AI (labeling vendor) exposed customer data and model outputs to labelers without proper safeguards.
- **Crowd-Source Labeling Attacks**: Researchers showed that crowd-source labelers can infer private information from model outputs they label (e.g., patient IDs from medical records).

### Tier 1: Essential Mitigations

#### 1.1 Data Minimization for HITs
**Implement**:
- Don't send full conversations. Send only the snippet requiring judgment.
- Example:
  ```
  ❌ Full conversation:
  User: "I have diabetes and take insulin."
  Assistant: "Make sure to monitor your blood sugar."
  [60 turns of conversation]

  ✅ Snippet for labeling:
  Last turn:
  User: "Any other tips?"
  Assistant: "Stay hydrated and exercise regularly."

  Task: "Is this response helpful? (yes/no)"
  ```

#### 1.2 Vendor Security Requirements
**Implement**:
- Require labeling vendors to sign Data Processing Agreements (DPA) with clauses:
  - No data copying, printing, or exporting.
  - No training on labeled data.
  - Background checks for all labelers.
  - Encryption at rest and in transit.
  - Compliance with SOC 2 or ISO 27001.

**DPA Checklist**:
```
☐ Data Minimization: Vendor agrees to minimize data exposure.
☐ Access Control: Only authorized labelers can view data.
☐ Background Checks: All personnel vetted (criminal records check, reference checks).
☐ Encryption: Data encrypted in transit (TLS 1.2+) and at rest (AES-256).
☐ Data Retention: Data deleted upon completion; no permanent storage.
☐ Subprocessors: Vendor discloses all subprocessors; customer can object.
☐ Audit Rights: Customer can audit vendor's security practices.
☐ Breach Notification: Vendor notifies customer promptly of suspected breach.
☐ Insurance: Vendor maintains cyber liability insurance.
```

#### 1.3 Tiered Reviewer Access
**Implement**:
- Only senior reviewers see sensitive labels.
- Junior reviewers see redacted or synthetic versions.
- Example:
  ```
  Sensitive data (SSN, medical): Only Senior Reviewers
  Moderately sensitive (customer name, email): Mid-level Reviewers
  Non-sensitive (sentiment, topic): Junior Reviewers
  ```

**Implementation**:
```python
def assign_labeling_task(hit_id, sensitive_level, labeler_id):
    labeler_tier = get_labeler_tier(labeler_id)  // junior, mid, senior

    if sensitive_level == "HIGH":
        if labeler_tier != "senior":
            raise UnauthorizedError("Only senior reviewers can access high-sensitivity data")
    elif sensitive_level == "MEDIUM":
        if labeler_tier == "junior":
            raise UnauthorizedError("Junior reviewers cannot access medium-sensitivity data")

    assign_task(hit_id, labeler_id)
```

#### 1.4 Task Partitioning
**Implement**:
- Split sensitive data across labelers so no single person sees the full record.
- Example:
  ```
  Record: Customer ID, Diagnosis, Treatment Date, Cost

  Labeler A sees: [Customer ID, Diagnosis]
  Labeler B sees: [Treatment Date, Cost]
  Labeler C sees: [Diagnosis, Treatment Date]

  No single labeler sees the full record.
  ```

**Implementation**:
```python
def partition_sensitive_record(record, num_partitions=3):
    """
    Split record across labelers so no one sees the full thing.
    """
    fields = list(record.keys())
    random.shuffle(fields)

    partitions = [dict() for _ in range(num_partitions)]

    for i, field in enumerate(fields):
        partition_idx = i % num_partitions
        partitions[partition_idx][field] = record[field]

    return partitions

# Usage
record = {"customer_id": "C123", "diagnosis": "Diabetes", "date": "[REDACTED]", "cost": "$500"}
partitions = partition_sensitive_record(record, num_partitions=3)

// Labeler A: {"customer_id": "C123", "diagnosis": "Diabetes"}
// Labeler B: {"date": "[REDACTED]"}
// Labeler C: {"cost": "$500"}
```

---

### Tier 2: Hardened Controls

#### 2.1 Synthetic Data for Non-Verbatim Tasks
**Implement**:
- Use synthetic prompts/completions for training data that doesn't require real user examples.
- Example: For training a classifier to detect "helpful vs. unhelpful", use synthetic examples rather than real support conversations.

**When to Use Synthetic**:
- Classification tasks (sentiment, intent): Synthetic works well.
- Retrieval/ranking: Needs real examples; harder to replace.
- RLHF reward models: Harder to use synthetic; needs real human preferences.

#### 2.2 Differential Privacy for RLHF
**Implement**:
- Add noise during reward model training.
- Ensures labeling feedback doesn't overfit to individual preferences or leak rare examples.

```python
from opacus import PrivacyEngine

# Train reward model with DP
privacy_engine = PrivacyEngine(
    optimizer,
    sample_rate=0.01,
    noise_multiplier=1.5,
    max_grad_norm=1.0
)

for epoch in range(num_epochs):
    for batch in labeled_data:
        // Train reward model on labeling feedback
        loss = reward_model_loss(batch)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

// Achieved privacy: ε ≈ 3 (formal guarantee)
```

#### 2.3 Periodic Vendor Audits
**Implement**:
- Conduct security reviews of labeling vendors on a periodic schedule.
- Check:
  - Encryption implementations.
  - Access logs (who accessed what data, when).
  - Retention policies (was data actually deleted?).
  - Personnel vetting (background checks performed?).

**Audit Checklist**:
```
Annual Vendor Security Audit:

☐ Encryption Verification
   - Is data encrypted at rest? (AES-256?)
   - Is data encrypted in transit? (TLS 1.2+?)
   - Are keys managed securely? (KMS?)

☐ Access Logs Review
   - Are all data accesses logged?
   - Are logs integrity-protected?
   - Any suspicious access patterns?

☐ Data Deletion Verification
   - Can vendor prove data was deleted?
   - Are backups also deleted?
   - Deletion verified within agreed timeframe?

☐ Personnel Vetting
   - Background checks performed on all labelers?
   - Are checks renewed periodically?
   - Any red flags in personnel records?

☐ Compliance Status
   - Current SOC 2 Type II report?
   - ISO 27001 certification current?
   - Any recent breaches or incidents?

☐ Subprocessor Review
   - List of all subprocessors.
   - Are subprocessors vetted?
   - Any changes since last audit?

Outcome: Pass / Fail / Pass with Conditions
Next Audit Date: [Schedule periodic follow-up]
```

---

### Tier 3: Defense-in-Depth

#### 3.1 On-Premises Labeling Teams
**Implement**:
- For highest-sensitivity data, maintain internal labeling staff.
- Employees (not contractors) with strict NDAs and security clearances.
- On-site or managed VPN access only.

**Requirements**:
- Background checks (criminal, financial, reference).
- Security clearance (for government/high-security contracts).
- NDA + data handling agreement.
- Periodic security training.
- No personal devices in labeling area (use company-owned equipment).
- Air-gapped systems (no internet access during labeling).

#### 3.2 Decoy Records in Labeling Batches
**Implement**:
- Seed labeling batches with canary records (fake data).
- Monitor for exfiltration.

```python
def create_labeling_batch_with_canaries(real_records, batch_size=100):
    """
    Mix real records with canary records (fake data).
    """
    batch = real_records.copy()

    canaries = [
        {"text": "CANARY_001: fake customer email fake@example.test"},
        {"text": "CANARY_002: test SSN 999-99-9999"},
        {"text": "CANARY_003: fake API key sk-fake1234567890"},
    ]

    batch.extend(canaries)
    random.shuffle(batch)

    return batch

// Later: Monitor for canaries in leaked data
// If canary appears in logs, breach detected → alert security team
```
