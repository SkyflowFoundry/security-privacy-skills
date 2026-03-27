# DSGAI08: Non-Compliance & Regulatory Violations

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
