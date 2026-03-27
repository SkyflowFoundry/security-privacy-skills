# DSGAI21: Disinformation & Integrity Attacks via Data Poisoning

### Attack Vectors

**Training-Time Poisoning**: Adversary injects false data into training corpus:
- **Technique**: Submit false wiki entries, research papers, or synthetic data to dataset repos
- **Impact**: Model trains on false data, internalizes false beliefs, reproduces misinformation in outputs
- **Scale**: 0.1-1% of training data can cause measurable model behavior change
- **Example**: Train model on corpus containing "The earth is flat"; model learns association and reproduces claim

**Retrieval-Time Poisoning**: Adversary injects false data into knowledge stores queried at inference:
- **Technique**: Write false entries to wiki, knowledge base, threat intelligence feed
- **Impact**: When user queries system, poison data ranks high by relevance; retrieved and served as fact
- **Speed**: Deployed instantly; affects all users querying that knowledge store
- **Example**: Inject false API documentation into knowledge base; agent uses incorrect API calls

**Crisis-Time Amplification**: False data weaponized during high-stakes incidents:
- **Technique**: During zero-day disclosure or active incident, inject false mitigation steps, fake patches, misleading threat intelligence
- **Impact**: Organizations follow false guidance, waste response time, cause further damage
- **Historical**: Grok incident (unauthorized data injection causing disinformation)

### Detailed Mitigations by Tier

**Tier 1: Write-Access Controls, Source Provenance, Retrieval Transparency**

- **Write-Access Controls**: Treat knowledge stores like production infrastructure:
  - **Authentication**: All writes require authentication (no anonymous edits)
  - **Authorization**: Only approved writers can modify (not users, not external systems)
  - **Audit logging**: Every write logs: who, what, when, from where
  - **Approval workflows**: High-risk or critical knowledge requires human review before persistence
  - **Rollback capability**: Maintain version history; ability to revert malicious changes

- **Source Provenance Tracking**: Document origin of all data:
  - **For each knowledge entry**: Record original source (URL, document, system, timestamp)
  - **Integrity hash**: Cryptographic hash of data at ingestion; detect if modified
  - **Chain of custody**: Track every update; who changed what when
  - **Expiration tracking**: Mark data with "last verified" timestamp; stale data gets lower trust
  - **Source credibility**: Categorize sources (official documentation, peer review, crowdsourced)

- **Retrieval Source Transparency**: Always show origin:
  - **Citation requirement**: Every retrieved fact must include source citation
  - **Display source**: Agent/model response includes "Source: [document name], [date], [URL]"
  - **User inspection**: User can click source to verify (builds trust, enables fact-checking)
  - **Trust signals**: Show source credibility (official wiki: high trust, user forum: medium trust)

**Tier 2: Ingestion Anomaly Detection, Trust-Tiered Retrieval, Crisis Gates**

- **Anomaly Detection at Ingestion**: Monitor for suspicious data patterns:
  - **Volumetric spike detection**: Alert if data volume spikes unexpectedly (e.g., 10x normal ingestion rate)
  - **Statistical divergence**: Compare incoming data distribution to historical baseline; alert on divergence
  - **Content anomalies**: Detect if text patterns diverge (writing style change, vocabulary anomaly, topic shift)
  - **Source anomalies**: Alert if data arrives from unexpected source (new submitter, unusual geographic origin)
  - **Temporal patterns**: Flag if changes arrive at unusual times (night, weekends, outside normal business hours)

- **Trust-Tiered Retrieval Weighting**: Rank sources by trust:
  - **Official sources**: High trust (official documentation, regulatory bodies, product owners)
  - **Peer-reviewed**: Medium-high trust (published research, vendor documentation)
  - **Crowdsourced**: Medium trust (wiki edits, user forums, stack overflow)
  - **Unknown**: Low trust (user-submitted data, external feeds, unverified sources)
  - **Retrieval ranking**: Regardless of relevance score, rank high-trust sources first
  - **Confidence boosting**: High-trust sources boost model confidence; low-trust sources lower confidence

- **Crisis-Period Ingestion Gates**: Enhanced vigilance during incidents:
  - **Crisis detection**: Automated or manual trigger when zero-day/incident detected
  - **Ingestion pause**: Stop accepting new data from public sources during crisis
  - **Manual review**: All external data requires human review before use
  - **Heightened alert threshold**: Lower anomaly detection thresholds (fewer suspicious patterns need alerting)
  - **Incident playbooks**: Pre-defined decision trees for handling poisoning during incidents

**Tier 3: Adversarial Integrity Evaluation, Automated HITL, Dataset BOM**

- **Adversarial Integrity Evaluation**: Red-team data for poisoning resilience:
  - **Training data integrity test**: Attempt to inject poison into training data; measure model behavior change
  - **Retrieval data integrity test**: Inject false entries into knowledge base; measure if false data ranks high
  - **Adversarial attack simulation**: Craft poisoned entries designed to maximize impact
  - **Robustness score**: Quantify resilience (can model be poisoned with <1% corrupted data? How much corruption triggers failure?)
  - **Remediation testing**: Verify that poisoning can be detected and corrected (remove poison, retrain, verify behavior returns to baseline)

- **Automated HITL (Human-in-the-Loop) Triggers**: Escalate high-stakes decisions:
  - **Decision risk scoring**: Classify decisions by impact (high-stakes = requires HITL)
  - **Source divergence detection**: If retrieved sources disagree, trigger HITL (human decides which source is authoritative)
  - **Confidence thresholds**: If model confidence is low, trigger HITL (human reviews before acting)
  - **Novel data detection**: If data source is new or unverified, trigger HITL
  - **Crisis-period HITL**: During incidents, ALL automated decisions require human review
  - **Workflow**: Automated system prepares decision + evidence, human reviews, human approves/rejects

- **Dataset Bill of Materials (BOM)**: Document data lineage and integrity:
  - **For each dataset**:
    - **Inventory**: What data? How much? Which records?
    - **Source**: Where from? When ingested? By whom?
    - **Integrity attestation**: Checksum at ingestion time. Attestation that no data was modified.
    - **Lineage**: Where does this data feed? (Models, vectors, exports, downstream systems)
    - **Integrity status**: Known clean, tested for poison, flagged for review
  - **Versioning**: Dataset BOM tracks all versions; enables rollback if poisoning detected
  - **Audit trail**: Changes to BOM logged and auditable (compliance evidence)
