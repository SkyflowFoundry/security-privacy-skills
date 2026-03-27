# OWASP GenAI Governance & Compliance: Detailed Risk Analysis

## DSGAI03: Shadow AI & Unsanctioned Data Flows

### Attack Surface

Shadow AI occurs across five vectors:

1. **Consumer GenAI SaaS**: ChatGPT, Claude, Copilot, Gemini. Employees paste code, customer PII, API keys, architectural diagrams. Most common vector.

2. **Third-Party SaaS with Embedded AI**: Slack, Jira, Salesforce, Confluence. "AI-powered search" or "summarization" features silently analyze your data within vendor infrastructure.

3. **Startup/Niche ML Tools on Opportunistic Cloud Regions**: Unknown ML vendors deployed on AWS/GCP regions with lax data residency controls. Data crosses borders without tracking.

4. **Internally Built but Ungoverned AI**: Data science teams stand up fine-tuning, RAG systems on shared cloud accounts. No security review, no data classification, no vendor contracts.

5. **Legacy IT Apps with AI Features**: Enterprise software (Office 365 Copilot, Salesforce Einstein) rolled out with default-enabled AI. Data flows to Microsoft/Salesforce without explicit awareness.

### Detailed Mitigations by Tier

**Tier 1: Policy, Catalog, Contracts, DLP**

- **Shadow AI Policy**: Document prohibition on unapproved GenAI services. Define "approved" (security-reviewed, data protection contractual commitments). Tie to consequences (termination).

- **Central AI Service Catalog**: Maintain authoritative list of approved tools with:
  - Vendor security review status (passed/failed assessment)
  - Data protection commitments (no training on user input, deletion on request)
  - Pricing and licensing terms
  - Approved use cases (e.g., "analysis of synthetic data only")

- **Vendor Contracts**: Enforce contractual provisions:
  - Data retention: vendor must delete on request, no indefinite storage
  - Training opt-out: data cannot be used to train models or improve products
  - Cross-border restrictions: specify data residency (EU, US, etc.)
  - Incident response: breach notification promptly, cooperation with investigation
  - Sub-processor controls: vendor cannot re-delegate to third parties without approval

- **DLP (Data Loss Prevention)**: Deploy rules to detect:
  - PII patterns (SSN, credit card numbers, email addresses) exiting network to unapproved endpoints
  - Secrets (API keys, tokens, passwords) matching known internal patterns
  - Domain-specific patterns (customer account IDs, product source code)
  - Endpoint: web/email/cloud storage

- **CASB (Cloud Access Security Broker)**: Monitor SaaS usage for suspicious behaviors:
  - Bulk data downloads
  - Anomalous user agents
  - Access from untrusted geographies
  - Unencrypted data uploads

**Tier 2: Governed Alternatives, Data Minimization, DSPM/EDR**

- **Enterprise GenAI with Data Protection**: Operate or procure tools with contractual assurance:
  - Zero data retention (input deleted after response)
  - No model training on customer data
  - On-premises or private cloud deployment (optional)
  - SOC 2 Type II certification

- **Data Minimization Standards**: Before sending ANY data to external services:
  - Tokenize: replace PII with placeholder tokens (e.g., [CUSTOMER_ID] instead of "acme-corp-123")
  - Pseudonymize: remove direct identifiers but preserve relational structure
  - Synthetic data: use representative fake data for testing
  - Hash sensitive fields: send only hash digests, not plaintext

- **SaaS Maturity Assessments**: Before approving any third-party SaaS:
  - Conduct security assessment (CAIQ questionnaire, penetration test, SOC 2 review)
  - Evaluate AI-specific risks (does tool process sensitive data with GenAI? Is it transparent?)
  - Rate maturity: Tier 1 (basic access controls), Tier 2 (encryption, MFA), Tier 3 (advanced monitoring, incident response)
  - Approve only Tier 2+

- **DSPM (Data Security Posture Management)**: Monitor on-premises systems for data flows to cloud/external endpoints:
  - Continuous scanning for data in transit (DLP agents on endpoints)
  - Network-level monitoring (DNS, TLS interception, DHCP)
  - Behavioral analysis (detect unusual connection patterns)
  - Alert on PII detected in outbound traffic

- **EDR (Endpoint Detection & Response)**: Detect suspicious processes on user machines:
  - Monitor for PowerShell/terminal commands accessing unapproved APIs
  - Track browser plugins and extensions
  - Log clipboard access (detect copy-paste of sensitive data)
  - Incident response: isolate machine, capture logs, notify user

**Tier 3: Continuous Discovery, AI Procurement Integration**

- **Continuous Shadow AI Discovery**: Implement ongoing visibility:
  - Network traffic analysis: identify encrypted connections to GenAI providers (SNI inspection, behavioral profiling)
  - DNS monitoring: block DNS queries to unapproved GenAI domains (ChatGPT, Copilot)
  - Behavioral anomalies: detect conversations with GenAI patterns (token limit exploitations, jailbreak attempts)
  - Periodic risk assessments of detected shadow AI usage

- **AI Procurement Integration**: Embed AI security into standard procurement:
  - Require security review before any GenAI tool is purchased
  - Mandate vendor questionnaires (CAIQ, AI-specific data protection)
  - Include AI clauses in MSAs (data deletion, training opt-out, incident response)
  - Establish approval board with security, legal, compliance representatives

---

## DSGAI07: Data Governance, Lifecycle & Classification for AI Systems

### Three-Stage Compounding Failure

**Stage 1 - Unclassified Ingestion**: Data enters pipelines without sensitivity assessment. Personally Identifiable Information (PII), Protected Health Information (PHI), API keys, customer secrets, credentials—all unlabeled. Ingestion systems cannot enforce retention because they don't know what they hold.

**Stage 2 - Derived Artifact Persistence**: Raw data may be deleted, but derived artifacts persist. Embeddings created from sensitive data remain in vector stores indefinitely. Fine-tuning datasets archived without TTL. Backup snapshots contain deleted records. Logs from inference pipeline capture model inputs.

**Stage 3 - Lineage Gap = Unremediable Breach**: When a DSR (Data Subject Request) or breach occurs, you cannot answer: "Which models contain this person's data?" You cannot execute machine unlearning because you have no map from original data to model weights. You cannot prove GDPR Article 17 compliance because you cannot demonstrate deletion across all forms.

### Detailed Mitigations by Tier

**Tier 1: Classification Propagation & Pipeline Ingress Scanning**

- **Classification Schema**: Define standard taxonomy:
  - **Public**: Marketing content, documentation
  - **Internal**: Strategies, roadmaps (not publicly visible)
  - **Confidential**: Trade secrets, proprietary algorithms, customer lists
  - **Restricted**: PII, PHI, credentials, API keys, payment card data
  - For each: retention requirement (1 year, 3 years, indefinite), deletion process, encryption status

- **Propagation to Derived Artifacts**: When data is classified, extend classification:
  - **Embeddings**: inherit source classification. If source is Restricted, embeddings are Restricted.
  - **Fine-tuning datasets**: inherit classification of included records
  - **Backups**: maintain classification tag in backup metadata
  - **Logs**: inherit classification from inputs (redact Restricted data before logging, or encrypt logs)
  - **Vector store indexes**: tag vectors with source classification

- **Pipeline Ingress Scanning**: Install classifiers at entry points:
  - When data enters ingestion: scan for PII (SSN, email, phone), PHI (medical terms), credentials (password patterns, API key formats)
  - When data merges: re-scan merged dataset (classification may increase if either input is Restricted)
  - Automated tagging: apply labels based on detected patterns, require human review for high-confidence detections

- **Retention Enforcement**: Define and enforce TTLs:
  - Raw data: "Delete after 3 years" → raw records auto-deleted
  - Embeddings: "Delete when source deleted" → remove from vector store
  - Backups: "Delete when primary records deleted" → expire backup snapshots
  - Logs: "Delete after retention period expires" → purge inference logs

**Tier 2: Deletion Verification, TTL Enforcement, Data Catalog**

- **Deletion Verification Testing**: Conduct periodic tests:
  - Select sample records marked for deletion (from prior quarter)
  - Verify record is gone from primary database
  - Query vector store: confirm embeddings removed
  - Query backups: check snapshot retention (if within TTL, should exist; if expired, should not)
  - Query logs: confirm no traces in audit trails
  - Document results; escalate failures

- **TTL for Agent Context**: Restrict indefinite caching:
  - Agent conversation history: TTL per retention policy
  - Retrieved context from RAG: TTL per retention policy (do not cache indefinitely)
  - User session state: TTL matches session duration (do not persist across sessions)
  - Automated purge: trigger TTL deletion without manual intervention

- **Data Catalog with Mandatory Tags**: Build inventory:
  - Asset: Dataset name, location (which database, which S3 bucket)
  - Sensitivity: classification label (Public, Internal, Confidential, Restricted)
  - Owner: which team owns/maintains this data
  - Lineage: where does it feed (which models, which vector stores, which exports)
  - Retention: TTL, deletion process, responsible party
  - Compliance: which regulations apply (GDPR, HIPAA, CCPA, EU AI Act)
  - Require: no data asset goes into production without catalog entry

- **Automated Lifecycle Enforcement**: Remove manual deletion:
  - Retention policy engine: scan all assets at TTL threshold, trigger deletion automatically
  - Immutable audit log: record what was deleted, when, by whom (compliance proof)
  - Notification: notify asset owner before deletion, allow exception process
  - Fallback: if deletion fails, escalate to human review (data governance team)

**Tier 3: Lineage Registry, Artifact Inventory, Unlearning Readiness**

- **Data-to-Model Lineage Registry**: Build first-class artifact tracking every path:
  - **Raw record** → **Preprocessing** → **Feature store** → **Training dataset** → **Model version 1.0**
  - **Embedding generated at** → Vector store version 2.1
  - **LoRA fine-tune at** → Adapter version 0.5
  - **Quantized model at** → Inference version 1.2
  - Query interface: "Given this customer record, which models/embeddings contain derivatives?" → instant answer
  - Version control: maintain history of all lineage changes (audit trail for compliance)

- **Derived-Artifact Inventory**: Document every transformation:
  - Embeddings: source data + embedding model + timestamp
  - Fine-tuning datasets: raw records included + training run + model version
  - LoRA adapters: base model + training data + adapter version
  - Quantized models: original model + quantization method + deployment version
  - For each: retention policy, deletion readiness, compliance applicability

- **Machine Unlearning Readiness by Design**:
  - **Versioned data**: maintain snapshots of training datasets; enable retraining on subset
  - **Versioned models**: tag each model version with exact training dataset version
  - **Selective retraining process**: define workflow to retrain model excluding deleted records
  - **Cost estimation**: estimate retraining cost per DSR (inform consent/negotiation)
  - **Testing infrastructure**: maintain parallel models (trained with vs. without deleted data) to verify unlearning efficacy

---

## DSGAI08: Non-Compliance & Regulatory Violations

### Three Failure Patterns

**Pattern 1 - Unlawful Basis/Consent Failure**: Data ingested into training without documented lawful basis (GDPR Article 6) or consent (GDPR Article 7). Organization cannot demonstrate that data use was legally justified. At regulatory audit: "Why did you train on this customer data?" Answer: "We... had it in the database." Violation.

**Pattern 2 - Erasure Gap**: Organization deletes raw customer records in response to GDPR Article 17 (Right to Erasure). But model weights, embeddings, LoRA adapters, quantizations derived from that customer's data remain in production. Model continues to exhibit behavior influenced by deleted data. Regulator: "You deleted the raw record but left the derivative." Violation.

**Pattern 3 - Lineage Absence at Point of Obligation**: GDPR Article 30 (Records of Processing) requires documented chain from data collection to processing to storage. Without lineage, organization cannot document this chain. DSR arrives: "Remove all my data." Organization cannot identify all locations where data was processed/stored. Cannot execute deletion. Cannot prove compliance.

### Regulatory Framework

**GDPR (EU)**
- **Article 5 (Lawfulness)**: Processing must have lawful basis (consent, contract, legal obligation, vital interests, public task, legitimate interests). Must be documented.
- **Article 6 (Lawful Basis)**: Training data must satisfy one of six bases. Organization chooses basis at ingestion; documents in RoPA.
- **Article 17 (Right to Erasure)**: Data subject can request deletion. Organization must delete within the regulatory deadline across ALL forms (raw, derived, backups). Exceptions: legal obligation, public interest.
- **Article 22 (Automated Decision-Making)**: Decisions based solely on automated processing (including ML) require human review. Cannot deny rights based on automated decision without human review.
- **Article 30 (Records of Processing)**: Maintain documentation of ALL processing activities: what data, how collected, what for, who has access, how long retained, deletion process.

**HIPAA (US Healthcare)**
- **Minimum Necessary Rule**: Healthcare organizations can only use/disclose minimum PHI needed for stated purpose. Training data that is "too broad" violates minimum necessary.
- **Data Use Agreements (DUAs)**: Business associates must sign DUAs limiting use and requiring safeguards. DUAs must cover AI training.
- **Breach Notification**: Breach of >500 individuals triggers public notification. Incident response for AI systems must include breach analysis.

**CCPA/CPRA (California)**
- **Consumer Rights**: Right to access, delete, correct, port data
- **Opt-Out from Profiling/Training**: Consumers can opt out from "sale" (broad definition) and automated decision-making
- **Right to Deletion**: Delete consumer's personal information from databases AND derived predictions/models (CPRA Amendment)
- **Right to Correct**: Consumer can correct inaccurate data; organization must update training datasets

**EU AI Act (Article 10 enforcement timeline)**
- **Training Data Governance**: Organizations must document training data sources, licensing status, quality assessment, bias testing
- **Prohibited Datasets**: Cannot train on biometric data (face recognition), special categories (racial/ethnic origin, political opinion)
- **Transparency**: Must disclose to users that content was generated/modified by AI
- **High-Risk Systems**: Subject to conformity assessment; maintain technical documentation

**Colorado AI Act**
- **High-Risk AI Classification**: Decisions affecting legal rights or opportunities must undergo bias/discrimination testing
- **Opt-Out Rights**: Consumers can opt out of automated decision-making
- **Transparency**: Disclose use of AI in automated decisions affecting consumers

### Detailed Mitigations by Tier

**Tier 1: DPIA Process, Lawful Basis Documentation, Vendor Contracts**

- **Data Protection Impact Assessment (DPIA)**: Before training or deploying ANY AI system:
  - **Scope**: Identify data flowing into system
  - **Lawful Basis**: Document which Article 6 basis justifies this data use (consent, contract, legal obligation, vital interests, public task, legitimate interests). If legitimate interests, conduct balancing test (necessity vs. rights impact).
  - **Risks**: What could go wrong? (Model memorization of PII, bias against protected groups, unauthorized secondary use)
  - **Mitigations**: What controls prevent risks?
  - **Decision**: Approve, approve with conditions, or reject
  - **Extend to derivatives**: DPIA must cover embeddings, fine-tuning datasets, LoRA adapters—not just raw data
  - **Document**: Maintain DPIA report for regulator audit

- **Lawful Basis Documentation**: Record in data lineage maps:
  - For each dataset: which Article 6 basis applies?
  - CONSENT: Which users consented? When? Can they withdraw?
  - CONTRACT: Which contractual obligation necessitates this data?
  - LEGAL OBLIGATION: Which law requires processing?
  - VITAL INTERESTS: How does processing protect life/safety?
  - PUBLIC TASK: Which public sector function requires this?
  - LEGITIMATE INTERESTS: What interests? Necessity test passed? Rights balancing test passed?
  - Document: maintain evidence (consent records, contract copies, legal citations)

- **Purpose Documentation in Data Lineage**: Extend to vector stores and embeddings:
  - Purpose: For each dataset, state intended use (e.g., "Train recommendation model for e-commerce")
  - Secondary use prohibited: Unless data subject consents or regulator approves, cannot use for different purpose
  - Change of purpose: If purpose changes (retraining, new model version), re-assess lawful basis and obtain additional consent if needed

- **Vendor Contract Enforcement**: Ensure data protection in AI contracts:
  - **Data Processing Agreement (DPA)**: If using third-party AI service (SaaS fine-tuning, hosted embeddings), require DPA covering GDPR Article 28 obligations
  - **Liability**: Vendor is liable for breaches, not just "best efforts"
  - **Data transfer restrictions**: Specify which countries vendor can process data in
  - **Subprocessor approval**: Vendor cannot delegate to third parties without written approval
  - **Data deletion proof**: Vendor must provide deletion confirmation on request

**Tier 2: Consent Lifecycle in ML Pipelines, EU AI Act Readiness, RoPA Extension**

- **Consent Lifecycle in Training Pipelines**: Integrate consent management:
  - **Ingestion**: When data enters training, check consent status (did data subject consent to THIS use?)
  - **Withdrawal**: When consent withdrawn, immediately remove from active training datasets; add to exclusion list for next retraining
  - **Audit**: Periodic audit: sample training data, verify consent records exist
  - **Retraining**: When retraining, check all consents again (some may have been withdrawn)

- **EU AI Act Article 10 Readiness**: Prepare for August 2026 enforcement:
  - **Training Data Registry**: Document for each training dataset:
    - Source (proprietary, licensed, public, crowdsourced)
    - Licensing status (what rights do you have to use this data?)
    - Quality assessment (bias testing, completeness, accuracy)
    - Prohibited data (none of: biometric, special categories)
    - Compliance evidence (testing results, documented mitigations)
  - **Test for bias**: Before deploying AI system, test for discrimination:
    - Disparate impact testing: Does system produce different outcomes for protected groups?
    - Fairness metrics: Equalized odds, calibration, group balance
    - Remediation: If bias detected, adjust training data or model (retrain, debiasing techniques)
  - **Transparency requirement**: AI Act Article 52 requires disclosure to users that AI was used
  - **Conformity assessment**: For high-risk systems, maintain technical documentation for regulator review

- **RoPA Extension to AI Systems**: Expand Records of Processing:
  - **AI-specific RoPA entries**:
    - Training dataset: source, volume, sensitive categories (PII, PHI)
    - Model version: training date, dataset version, hyperparameters
    - Vector store: population date, source data classification, TTL
    - Fine-tuning: what data, which model, deployment date
    - Inference: which users access, for what purpose, what data processed
  - **Deletion process**: Document how deletion is executed for AI-specific artifacts (retraining without deleted records, embedding deletion, model versioning)
  - **Audit trail**: Log all changes to training data, model versions, vector stores

**Tier 3: Unlearning Architecture, Automated Compliance Monitoring**

- **Machine Unlearning Readiness Architecture**: Design systems for selective data removal:
  - **Data versioning**: Maintain snapshots of training datasets at each training run
  - **Model versioning**: Tag each model version with exact dataset version used
  - **Selective retraining process**:
    - DSR arrives for deletion
    - Identify all data derivatives (embeddings, fine-tunes, quantized models)
    - Retrain model excluding deleted records
    - Validate unlearning (new model produces different outputs for deleted-data scenarios)
    - Deploy new model version
  - **Resource estimation**: Calculate retraining effort per DSR (inform legal/business planning)
  - **Testing infrastructure**: Maintain models trained with vs. without deleted data; verify divergence

- **Automated Compliance Posture Monitoring**: Continuous verification:
  - **Lawful basis verification**: Regular scan of all datasets; alert if lawful basis is missing or unsupported
  - **Retention enforcement**: Automated TTL deletion for expired data; audit trail for all deletions
  - **Lineage integrity**: Periodic validation that lineage registry matches actual systems (if lineage says embedding exists, verify it's really in vector store)
  - **Consent validation**: Periodic check: are all training datasets still consented? If not, flag for remediation
  - **DSR response**: Automated workflow for DSR:
    - Accept request
    - Query lineage registry: identify all data derivatives
    - Trigger deletion/unlearning
    - Verify deletion completion
    - Respond to data subject within the regulatory deadline

---

## DSGAI20: Model Exfiltration & IP Replication

### Attack Methodology: Model Extraction via Legitimate API Access

**Distillation Attack**: Attacker uses public API access (paid or free tier) to extract model capabilities:

1. **Probing Phase**: Send diverse prompts (100K+ campaigns documented) to map model behavior
2. **Pattern Detection**: Analyze responses to identify underlying logic (classification thresholds, preference ordering, style patterns)
3. **Chain-of-Thought Coercion**: Request intermediate reasoning steps ("Show your work", "Explain step-by-step"). Internal reasoning is IP.
4. **Embedding Extraction**: Request embeddings from API. Analyze 100s of embeddings to reverse-engineer embedding space.
5. **Quantitative Analysis**: Statistical extraction of decision boundaries, probability calibration, internal representation

**Recent Campaigns** (Google Cloud Blog, Anthropic Feb 2026):
- Reasoning-trace coercion: Attackers found that multi-step reasoning outputs expose internal reasoning logic
- Sub-threshold probing: Conducted extraction over weeks at sub-alert-threshold query volumes
- Cross-prompt consistency: Designed prompts to measure consistency of model behavior across domains

### Detailed Mitigations by Tier

**Tier 1: Rate Limiting, ToS Enforcement, API Monitoring**

- **Rate Limiting**: Implement strict quotas:
  - Per-user quotas: X requests/hour, Y requests/day
  - Per-API-key quotas: Track aggregated usage across all users of a key
  - Burst protection: Allow occasional spikes, but penalize sustained high volume
  - Graceful degradation: Return 429 (Too Many Requests) before hard cutoff; provide retry-after header
  - Logging: Record all rate-limited requests for anomaly analysis

- **Terms of Service Enforcement**:
  - Include explicit prohibition on: extraction, distillation, reverse engineering, model reproduction
  - Include prohibition on: bulk data collection, automated probing, statistical analysis of outputs
  - Define consequences: API key suspension, account termination
  - Enforcement mechanism: Monitor ToS violations, escalate to legal/abuse team

- **API Access Monitoring**: Track suspicious patterns:
  - **Volume anomalies**: Sudden spike in requests from single key/user
  - **Pattern consistency**: Requests with repetitive structure (extraction campaigns have characteristic patterns)
  - **Time patterns**: 24/7 probing (humans don't), consistent intervals (bots do)
  - **Geographic anomalies**: Requests from unusual locations
  - **Output analysis**: Track if attacker is requesting same prompt repeatedly with minor variations (extraction signature)

**Tier 2: Behavioral Analytics, Output Perturbation, CoT Controls**

- **Behavioral Analytics**: Deploy ML-based detection:
  - **Embedding similarity**: Cluster requests by semantic similarity; high-clustering indicates extraction (attacker varies prompts but seeks same information)
  - **Output comparison**: Detect if attacker is comparing outputs (requesting same query + variations, recording results)
  - **Probing patterns**: Machine learning classifier trained on known extraction campaigns to identify similar behavior
  - **Adaptive thresholds**: Adjust sensitivity based on false positive rate; prioritize precision (don't block legitimate users)

- **Output Perturbation**: Degrade extraction signal without harming legitimate users:
  - **Probabilistic perturbation**: Add small random noise to output probabilities (softmax layer). Imperceptible to humans but degrading to statistical extraction.
  - **Embedding perturbation**: Add noise to embedding outputs. Adversary extracts noisy embeddings; utility for legitimate users preserved.
  - **Response variation**: For same query, occasionally return different (but equally correct) response. Breaks assumption of deterministic model behavior.
  - **Sampling mechanism**: Controlled degradation (don't break model completely); A/B test to ensure no user experience regression

- **Chain-of-Thought Controls**: Restrict reasoning trace outputs:
  - **Output verbosity controls**: Limit reasoning trace length; only show final answer to free tier
  - **Tiered access**:
    - Free tier: answer only, no reasoning
    - Standard tier: reasoning available, with perturbation
    - Enterprise tier: full reasoning, with query auditing
  - **Dynamic disabling**: If extraction campaign detected, disable CoT for that API key
  - **Reasoning tokenization**: Count reasoning tokens toward rate limits (makes extraction expensive)

**Tier 3: Output Watermarking, Adaptive Rate Limiting, Red-Team Extraction**

- **Output Watermarking**: Embed provenance markers:
  - **Text watermarking**: Insert imperceptible markers into generated text (e.g., word substitutions, synonym selection with hidden patterns)
  - **Embedding watermarking**: Add controlled signal to embeddings (detectable by model owner, imperceptible to others)
  - **Detection mechanism**: Verify watermark in suspicious samples; proves origin
  - **Legal backing**: Watermark serves as evidence of unauthorized model reproduction (copyright infringement)

- **Adaptive Rate Limiting**: Tighten limits based on extraction risk:
  - **Similarity scoring**: Compute similarity of current requests to historical extraction campaign patterns
  - **Dynamic thresholds**: High-extraction-risk profiles get lower rate limits (e.g., 10 req/hour instead of 100)
  - **Escalating penalties**: Repeated high-risk behavior triggers progressively stricter limits
  - **Whitelist/blacklist**: Known research institutions get relaxed limits; known extraction operators get blocked

- **Periodic Extraction Red-Teaming**: Validate defenses:
  - **Simulate attack**: Conduct regular extraction campaigns using own API
  - **Measure efficacy**: Compare extracted model to original; measure divergence (should be high)
  - **Test detection**: Verify that attack was detected by monitoring system (should have alerted)
  - **Tune defenses**: Adjust perturbation levels, rate limits, behavioral thresholds based on results
  - **Report**: Document test results, recommendations for improvement

---

## DSGAI21: Disinformation & Integrity Attacks via Data Poisoning

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

---

## Implementation Sequence & Phases

**Phase 1: Foundation**
- Shadow AI policy documented and communicated
- AI service catalog established with security assessments
- Data classification schema defined and applied to ingestion pipelines
- DPIA template created; preliminary DPIA for high-risk systems

**Phase 2: Detection & Enforcement**
- DLP/CASB deployed and configured
- Rate limiting implemented on APIs
- Data-to-model lineage registry established for new systems
- Lawful basis documented in data lineage maps

**Phase 3: Automation & Monitoring**
- Automated lifecycle enforcement (TTL deletion)
- API behavioral analytics deployed
- Anomaly detection for shadow AI (DSPM/EDR)
- Recurring compliance audits automated

**Phase 4: Hardening & Red-Teaming**
- Extraction red-teaming conducted
- Data poisoning simulation executed
- Output perturbation/watermarking evaluated
- Crisis-period ingestion gates tested
- Advance to Tier 3 for highest-risk systems

---

## Incident Response & Case Studies

**Case Study 1: Shadow AI Data Breach**
- Employee pastes customer PII into ChatGPT for summarization
- DLP detects exfiltration, alerts security team
- Security confirms: 50K customer records exposed
- Response: Notify OpenAI, request data deletion, conduct GDPR Article 33 incident notification, shadow AI policy enforcement

**Case Study 2: Model Extraction Campaign**
- Security team observes 100K+ API requests from single actor
- Requests exhibit extraction campaign signature (prompt variation, output comparison)
- Rate limiting triggers; API key suspended
- Analysis: Attacker successfully extracted decision boundaries (70% accuracy replica model)
- Remediation: Deploy output perturbation, conduct extraction red-team on a recurring basis

**Case Study 3: Data Poisoning Attack**
- Attacker injects false security patches into internal knowledge base
- Agent retrieves poison during incident response; recommends false remediation
- HITL checkpoint catches issue (human reviewer found source fishy)
- Response: Enable crisis-period ingestion gates, retrain on clean data, implement source provenance tracking

---

## Compliance Checklists

**GDPR Readiness**
- [ ] DPIA conducted before training/deployment
- [ ] Lawful basis documented for all training data
- [ ] Data-to-model lineage registry operational
- [ ] DSR workflow automated (identify, delete, unlearn)
- [ ] RoPA extended to AI systems
- [ ] Deletion verification tests run on a recurring schedule

**HIPAA Readiness**
- [ ] Minimum necessary rule applied to training data
- [ ] DUAs signed with all vendors
- [ ] Data use audit trail maintained
- [ ] Breach response procedures for AI systems

**CCPA/CPRA Readiness**
- [ ] Consumer opt-out mechanism implemented
- [ ] Data deletion extends to model weights/embeddings
- [ ] Automated deletion workflow tested
- [ ] Transparency reports prepared

**EU AI Act Readiness**
- [ ] Training data registry complete
- [ ] Bias testing completed and documented
- [ ] High-risk classification and conformity assessment done
- [ ] Technical documentation prepared for regulator
- [ ] Transparency disclosures implemented

---

## Tools & Technologies

**Shadow AI Detection**
- CASB: Microsoft Defender for Cloud Apps, Netskope, Zscaler
- DSPM: Varonis, Alation, Collibra
- EDR: CrowdStrike, Microsoft Defender, SentinelOne

**Data Governance**
- Catalog: Collibra, Alation, Apache Atlas
- DLP: Microsoft 365 DLP, Symantec DLP, Forcepoint
- Lineage: Datahub, OpenLineage, Looker, Tableau

**Compliance Automation**
- DPIA: OneTrust, TrustArc
- RoPA management: OneTrust, Compliance.ai
- DSR workflow: OneTrust, Titus, BigID

**API Security & Monitoring**
- Rate limiting: Kong, AWS API Gateway, Cloudflare
- Behavioral analytics: Datadog, New Relic
- Watermarking: SurePoint, Mnemonic

**Data Integrity & Poisoning Defense**
- Anomaly detection: Grafana, Datadog, New Relic
- Version control: Git, DVC (Data Version Control)
- HITL platforms: Labelbox, Scale AI, Surge
