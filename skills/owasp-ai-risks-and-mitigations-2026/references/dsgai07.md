# DSGAI07: Data Governance, Lifecycle & Classification for AI Systems

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
