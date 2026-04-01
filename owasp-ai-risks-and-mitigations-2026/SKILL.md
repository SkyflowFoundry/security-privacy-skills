---
name: owasp-ai-risks-and-mitigations-2026
description: "Assess and remediate all 21 OWASP GenAI data-security risks (DSGAI 2026). Covers data protection, agent & pipeline security, and governance compliance with tiered mitigations, a 6-step assessment workflow, and regulatory mapping for GDPR, HIPAA, CCPA, EU AI Act, and Colorado AI Act."
---

# OWASP GenAI Data Security Risk Framework (DSGAI 2026)

Your GenAI systems are only as secure as their weakest data integration point. This skill covers all **21 DSGAI risks** across three interconnected security domains—use it to assess your current posture, look up mitigations for a specific risk, or run a full security review.

**Data Protection**: How data flows in and out of your GenAI system without leaking to unintended parties. Risks: DSGAI01, 09, 10, 11, 14, 15, 18, 19.

**Agent & Pipeline Security**: How your GenAI components interact safely with tools, data stores, APIs, and each other. Risks: DSGAI02, 04, 05, 06, 12, 13, 16, 17.

**Governance & Compliance**: How your organization controls GenAI deployments, enforces data policies, and stays compliant. Risks: DSGAI03, 07, 08, 20, 21.

Each risk has three mitigation tiers: **T1 (Essential)** — foundational controls every system needs; **T2 (Hardened)** — consistent enforcement and design changes; **T3 (Defense-in-Depth)** — mature, measured, adaptive controls for high-risk systems.

## Output Constraints

When producing assessments, roadmaps, or remediation plans:

- **No time estimates.** Do not specify days, weeks, months, quarters, or years. Use sequential phases without durations. Say "periodic" or "regular" instead of "quarterly" or "monthly."
- **No dollar amounts.** Do not estimate costs, budgets, fines, or penalties. Focus on the risk and the control, not the price tag.

---

## Quick Reference: All 21 DSGAI Risks

| ID | Risk Name | Primary Threat | Domain |
|----|-----------|----------------|--------|
| DSGAI01 | Sensitive Data Leakage | PII/secrets in model outputs or logs | Data Protection |
| DSGAI02 | Agent Identity & Credential Exposure | Stolen API keys, database passwords | Agent & Pipeline |
| DSGAI03 | Shadow AI & Unsanctioned Data Flows | Unapproved GenAI systems using proprietary data | Governance |
| DSGAI04 | Data, Model & Artifact Poisoning | Malicious training data corrupts model behavior | Agent & Pipeline |
| DSGAI05 | Data Integrity & Validation Failures | Invalid/corrupted data accepted without checks | Agent & Pipeline |
| DSGAI06 | Tool, Plugin & Agent Data Exchange Risks | Unsafe data passing between GenAI and integrations | Agent & Pipeline |
| DSGAI07 | Data Governance, Lifecycle & Classification | Unclear ownership/retention/classification of AI data | Governance |
| DSGAI08 | Non-Compliance & Regulatory Violations | GDPR, HIPAA, CCPA, EU AI Act requirements not met | Governance |
| DSGAI09 | Multimodal Capture & Cross-Channel Data Leakage | Images, audio, documents leak across pipelines | Data Protection |
| DSGAI10 | Synthetic Data, Anonymization & Transformation Pitfalls | Synthetic data re-identifies PII; poor anonymization | Data Protection |
| DSGAI11 | Cross-Context & Multi-User Conversation Bleed | User A's data visible to User B via context collision | Data Protection |
| DSGAI12 | Unsafe Natural-Language Data Gateways | LLM-generated SQL/GraphQL queries allow injection | Agent & Pipeline |
| DSGAI13 | Vector Store Platform Data Security | Unauthorized access to embeddings; data exfiltration | Agent & Pipeline |
| DSGAI14 | Excessive Telemetry & Monitoring Leakage | Logs and metrics leak sensitive tokens/patterns | Data Protection |
| DSGAI15 | Over-Broad Context Windows & Prompt Over-Sharing | Full database context sent to model; data shared externally | Data Protection |
| DSGAI16 | Endpoint & Browser Assistant Overreach | Browser extensions, client-side agents over-access data | Agent & Pipeline |
| DSGAI17 | Data Availability & Resilience Failures in AI Pipelines | Data pipelines fail; no fallback; stale/corrupted data served silently | Agent & Pipeline |
| DSGAI18 | Inference & Data Reconstruction | Attackers reverse-engineer training data from outputs | Data Protection |
| DSGAI19 | Human-in-the-Loop & Labeler Overexposure | Crowd workers, contract labelers see sensitive data | Data Protection |
| DSGAI20 | Model Exfiltration & IP Replication | Proprietary model weights or behavior copied via API probing | Governance |
| DSGAI21 | Disinformation & Integrity Attacks via Data Poisoning | Malicious data injected to produce harmful outputs | Governance |

---

## Data Protection Risks

### DSGAI01: Sensitive Data Leakage

**Threat**: Attackers craft prompts to extract PII, PHI, or secrets from model weights or RAG indexes. Fine-tuned models memorize rare training examples verbatim. Error messages, logs, and telemetry leak unredacted responses.

**Why it matters**: A single exposure of customer SSNs, medical records, or API keys triggers GDPR fines, HIPAA violations, and operational chaos.

| Tier | Mitigations |
|------|-------------|
| **T1** | Data minimization at source (strip/mask PII before indexing into RAG or training datasets); DLP on all model outputs (regex + ML detectors for SSN, credit card, email; watch for cross-lingual bypass); rate-limit extraction attempts (cap queries per user/session; monitor prompt enumeration); output redaction policies (no-train, no-retain at API-provider level) |
| **T2** | Differential privacy on fine-tuning (DP-SGD/LoRA to bound memorization); format-preserving encryption (FPE) for PII in storage; prompt architecture hardening (system prompts forbid returning training data verbatim); per-user/tenant RAG partitioning with authorization enforced at retrieval time |
| **T3** | Membership inference audits to detect memorized rare training samples; transient storage with short TTLs for indexed documents and intermediate representations; machine unlearning readiness (design data governance now to support on-request removal) |

See also: [Full details & implementation guidance](./references/dsgai01.md)

---

### DSGAI09: Multimodal Capture & Cross-Channel Data Leakage

**Threat**: User-uploaded screenshots, audio recordings, and documents are transcribed via OCR/ASR and stored without PII classification or retention controls. Derived artifacts (embeddings, summaries) propagate across multiple storage systems with no lifecycle governance.

**Why it matters**: A screenshot of a patient record is as sensitive as the source document but treated as a casual image. Transcripts of financial calls get logged and never purged.

| Tier | Mitigations |
|------|-------------|
| **T1** | Tag all uploads as potentially PII-bearing with short retention windows; run OCR/ASR PII detection before indexing (quarantine hits); training opt-out for all user-submitted audio/images without explicit consent; derivative tagging (apply same ACLs and retention to embeddings/summaries as to source) |
| **T2** | On-device preprocessing where possible (upload only redacted text or vectors, not raw files); multimodal red-teaming (test whether models leak PII from adversarial image prompts) |
| **T3** | Fine-grained retention policies per channel (different TTLs for chat history vs. archived documents vs. embeddings); automated purge workflows |

See also: [Full details & implementation guidance](./references/dsgai09.md)

---

### DSGAI10: Synthetic Data, Anonymization & Transformation Pitfalls

**Threat**: Anonymization is reversed via quasi-identifiers (age + zip + gender). Synthetic data generated from sensitive datasets memorizes rare records. Data transformations (normalization, filtering) introduce subtle statistical leakage paths.

**Why it matters**: You publish "anonymized" data thinking it's safe, but a researcher re-identifies patients. Your synthetic dataset reproduces a single identifiable record because it was rare in the training set.

| Tier | Mitigations |
|------|-------------|
| **T1** | Treat synthetic data as potentially personal (apply strict retention/access policies); quasi-identifier suppression (coarsen fields: age ranges, regional zip, generalized demographics); Dataset Bill of Materials (document lineage, transformations, known quasi-identifiers); enforce consistent transformation rules across teams |
| **T2** | Disclosure risk measurement (calculate k-anonymity or l-diversity; require k≥5 minimum); transformation testing (validate no statistical leakage via mode/variance analysis) |
| **T3** | Differential privacy for synthetic generation on high-risk cohorts (trade utility for formal privacy guarantees when quasi-identifiers are inherent) |

See also: [Full details & implementation guidance](./references/dsgai10.md)

---

### DSGAI11: Cross-Context & Multi-User Conversation Bleed

**Threat**: Shared KV caches, vector indexes, or session memory leak data between users or tenants. Bugs in session management or tenant routing allow one user to query another's conversation history or retrieve cross-organization documents.

**Why it matters**: A SaaS platform accidentally returns User B's conversation to User A. Multi-tenant RAG systems that skip tenant_id filtering at query time bleed data silently—discovery is often delayed.

| Tier | Mitigations |
|------|-------------|
| **T1** | Tenant ID enforcement at every layer (queries, indexes, caches; fail closed if context is unclear); per-tenant vector indexes or physical partitions (no shared index with retrieval-time filtering only); auth-bound session isolation (tie tokens to user/tenant identity; invalidate on logout; never reuse session IDs); cross-tenant access logging with mismatch alerts |
| **T2** | ABAC at retrieval time (fine-grained policies enforcing ownership, sensitivity, and role); KV-cache isolation (namespace by user session; never share across requests) |
| **T3** | Automated cross-tenant bleed testing (periodic pentests including timing attacks and cache hit/miss inference) |

See also: [Full details & implementation guidance](./references/dsgai11.md)

---

### DSGAI14: Excessive Telemetry & Monitoring Leakage

**Threat**: Debug logs capture full prompts, responses, tool outputs, and credentials. Observability platforms become exfiltration targets. Misconfigured logging ships data to third-party vendors without sanitization.

**Why it matters**: A developer logs a full API response to debug an error; that response contains a customer's medical history; the log ships to a SaaS logging service; a breach of that service exposes everything.

| Tier | Mitigations |
|------|-------------|
| **T1** | Least-logging principle (log entry/exit and errors, not payloads; redact PII before any logging); automated PII scanning on log output (quarantine or redact before shipping to observability backend); retention aligned with data lifecycle (logs don't outlive source data); third-party vendor controls (require DPA, encryption, limited log scope) |
| **T2** | Tiered debug sessions with expiry (verbose logging only during troubleshooting windows; require re-auth to extend); hardened observability RBAC (role-restricted log access; mTLS between services and logging backend); automated PII alert on high-confidence detections |
| **T3** | Internal-only observability for sensitive data paths (avoid third-party SaaS logging); log-level isolation (different retention and access per level; purge debug logs on a regular cadence) |

See also: [Full details & implementation guidance](./references/dsgai14.md)

---

### DSGAI15: Over-Broad Context Windows & Prompt Over-Sharing

**Threat**: Teams pack prompts with full user profiles, conversation histories, or database records. Prompts sent to external APIs are cached globally or logged. Large context windows amplify data volume at risk per query.

**Why it matters**: Including a customer's full purchase history in a prompt to an external API that retains logs puts your customer data in someone else's system without a breach.

| Tier | Mitigations |
|------|-------------|
| **T1** | Data minimization at the prompt layer (include only the specific context needed for the question; exclude full profiles, full histories, unrelated records); prompt shaper middleware (strip sensitive fields before sending to external models); prompt size limits per request; internal-vs-external routing (sensitive queries to internal models only) |
| **T2** | Contractual LLM provider controls (require no data retention, no training on logs, audit rights in API agreements); privacy-by-design reviews before deploying any agent or RAG system (map all external API calls; require approval for any PII) |
| **T3** | Prompt encryption in transit to external APIs; decoy/canary tokens in prompts to detect leakage in vendor telemetry |

See also: [Full details & implementation guidance](./references/dsgai15.md)

---

### DSGAI18: Inference & Data Reconstruction

**Threat**: Attackers run membership inference attacks (determine if a record was in training data), model inversion (recover training examples from gradients), or embedding inversion (reconstruct text from vectors). RAG systems with loose ACLs amplify the attack surface.

**Why it matters**: A competitor runs targeted queries to determine which customers appear in your training data. An attacker inverts embeddings to recover proprietary documents indexed in your RAG system.

| Tier | Mitigations |
|------|-------------|
| **T1** | Access throttling and query budgets (rate-limit per user/API key; require approval for bulk queries); output confidence bounding (no exact probabilities; return coarse bins or binary answers); vector store ACLs enforced at retrieval time; k-NN restrictions (limit to top-1 to top-3 results; no full rankings) |
| **T2** | Differential privacy for fine-tuning (DP-SGD/LoRA for formal membership-inference guarantees); embedding noise injection (degrade inversion signal while preserving utility); LoRA extractability audits (test whether adapters can be extracted via adversarial queries) |
| **T3** | Periodic membership inference audits (measure TP/FP rates; adjust DP and throttling accordingly); shadow membership red-teaming (held-out records to verify non-memorization) |

See also: [Full details & implementation guidance](./references/dsgai18.md)

---

### DSGAI19: Human-in-the-Loop & Labeler Overexposure

**Threat**: RLHF and labeling pipelines expose raw prompts and model completions to human labelers at scale. Labelers see unredacted user data, secrets, and PII. Vendor and crowd-platform security controls are often weak.

**Why it matters**: A labeling vendor breach exposes 100K prompt-completion pairs containing customer data. A disgruntled labeler copies raw data to removable storage.

| Tier | Mitigations |
|------|-------------|
| **T1** | Data minimization for HITs (send only the snippet requiring judgment, not full conversation history); vendor security requirements (DPAs/BAs with no-copy, no-training-on-data, background-check, encryption clauses); tiered reviewer access (senior reviewers only for sensitive labels; junior reviewers see redacted/synthetic versions); task partitioning (split sensitive data across labelers so no single person sees a complete record) |
| **T2** | Synthetic data for non-verbatim labeling tasks; DP for RLHF reward model training (noise during training prevents overfitting to individual preferences); periodic vendor audits (encryption, access logs, retention policies, personnel vetting) |
| **T3** | On-premises labeling for highest-sensitivity data (strict NDAs, security clearances); decoy records seeded into labeling batches to detect exfiltration |

See also: [Full details & implementation guidance](./references/dsgai19.md)

---

## Agent & Pipeline Security Risks

### DSGAI02: Agent Identity & Credential Exposure

**Threat**: AI agents accumulate non-human identities (service accounts, API keys, OAuth tokens) with no lifecycle governance. Three-legged OAuth designed for humans is bolted onto autonomous agents. Agents inherit full operator tokens and propagate them downstream without re-scoping. NHI (non-human identity) sprawl creates persistent exfiltration paths.

**Why it matters**: A single leaked agent token with broad scope compromises every API, database, and service the agent can reach. Unlike human credentials, agent tokens are stored in environment variables or config files and often have long TTLs—creating persistent attack windows.

| Tier | Mitigations |
|------|-------------|
| **T1** | Enforce least-privilege RBAC/ABAC; short-lived tokens for all agent operations; mTLS for agent-to-service communication; secret vault with RBAC (no plaintext env vars); immutable audit logs; rotate secrets on a regular schedule |
| **T2** | Task-scoped OAuth (client credentials flow, not delegated user tokens); NHI inventory and lifecycle tracking; anomaly detection alerting on new IPs or unusual tool access patterns; per-agent PKI certificates |
| **T3** | Workload identity federation (Kubernetes SPIFFE/OIDC, GCP Workload Identity); signed agent requests (JWS); ephemeral agent memory (no persistent credential caching); continuous NHI governance |

See also: [Full details & implementation guidance](./references/dsgai02.md)

---

### DSGAI04: Data, Model & Artifact Poisoning

**Threat**: Three-stage attack: (1) Supply chain—typosquatted packages, malicious model files, compromised hub tokens. (2) Artifact tampering—modified preprocessing scripts disable differential privacy; chat templates embed backdoors. (3) Poisoning at ingestion—250 poisoned samples can produce measurable impact; GGUF files and inference-time artifacts become Trojan horses.

**Why it matters**: Training data poisoning is silent—models train normally but encode hidden triggers. Detection is hard because poisoning is indistinguishable from natural outliers. Compromised artifacts downstream reach all inference calls without signature verification.

| Tier | Mitigations |
|------|-------------|
| **T1** | Ingestion controls and package hygiene (lock deps; pin hashes); golden datasets and canary evaluation; registry write protection and promotion gates; secret scanning; access control on artifact store |
| **T2** | Cryptographic signing (COSE/Sigstore) across the artifact chain; DBOM (CycloneDX ML) for model supply chain visibility; anomaly detection on embedding outliers; privacy control regression testing |
| **T3** | Reproducible deterministic builds; supplier attestation (SLSA framework); red-team backdoor trigger testing; runtime behavioral monitoring; continuous re-baselining |

See also: [Full details & implementation guidance](./references/dsgai04.md)

---

### DSGAI05: Data Integrity & Validation Failures

**Threat**: Schema and semantic validation is bypassed. Malformed CSV/JSON/Parquet passes syntax checks but corrupts training. Import path traversal enables arbitrary file write via snapshot deserialization.

**Why it matters**: Validation is often single-layer (schema only). Semantically valid but malicious data (e.g., label-flip attacks) slips through. Symlinks and path traversal in import paths turn file uploads into arbitrary write primitives.

| Tier | Mitigations |
|------|-------------|
| **T1** | Strict schema enforcement (JSON Schema, Avro, Parquet contracts); block structurally valid but semantically suspicious data; sanitize filenames; refuse symlinks; cryptographic integrity checks (SHA-256); immutable audit trail |
| **T2** | Hardened import paths (chroot, container jail); SELinux/AppArmor confinement on ingestion processes; read-only mounts for input data; ingestion anomaly detection |
| **T3** | Semantic validation (statistical bounds, relationship consistency checks); defense-in-depth (non-root processes, capability dropping); runtime data validation at use time, not just at ingestion |

See also: [Full details & implementation guidance](./references/dsgai05.md)

---

### DSGAI06: Tool, Plugin & Agent Data Exchange Risks

**Threat**: Conversation payloads drain to plugin backends and can be corrupted after plugin updates. A2A (agent-to-agent) and MCP (Model Context Protocol) lack mutual authentication by default. Tool poisoning—malicious MCP server metadata tricks the model into calling unintended tools.

**Why it matters**: Unvetted plugins collect full conversation context. Compromised MCP servers can turn tool calls into command execution, and the model has no built-in mechanism to verify tool identity.

| Tier | Mitigations |
|------|-------------|
| **T1** | Allow-list governance with continuous review; kill-switch capability per tool; context minimization (pass only required fields to each tool call); central observability (all tool calls logged with caller identity) |
| **T2** | Agent and server identity verification (PKI certs, Agent Cards for A2A; per-server auth for MCP); transport security (mTLS and signed messages); task-scoped credentials per tool invocation |
| **T3** | Consequence-based authorization (permit tool X only if agent hasn't called tool Y in this session); OS-level container sandboxing per tool call; behavioral red-teaming of tool exchange |

See also: [Full details & implementation guidance](./references/dsgai06.md)

---

### DSGAI12: Unsafe Natural-Language Data Gateways (LLM-to-SQL/Graph)

**Threat**: "Ask your data" copilots generate raw SQL or GraphQL over wide schemas. Prompt-to-query injection, privilege amplification (the model inherits the DB user's full schema access), and text-to-SQL backdoors allow attackers to extract or corrupt data.

**Why it matters**: The model becomes a SQL query builder with user-supplied prompts as input. Injection bypasses parameterization. The model's authority equals the database user's authority—if that's full schema access, so is the attacker's.

| Tier | Mitigations |
|------|-------------|
| **T1** | Never allow the LLM to generate arbitrary SQL—use stored procedures and parameterized templates only; row/column-level security enforced at the DB layer regardless of query source; ACL enforcement; rate limiting; result-set size caps |
| **T2** | Query validation and linting (detect DROP, ALTER, TRUNCATE before execution); prompt injection hardening (instruction-following evaluation against adversarial inputs); test coverage for edge cases and boundary conditions |
| **T3** | Red-team text-to-SQL agents for SQL injection, privilege escalation, and inference-time backdoors; semantic query validation; context-aware result filtering |

See also: [Full details & implementation guidance](./references/dsgai12.md)

---

### DSGAI13: Vector Store Platform Data Security

**Threat**: Unencrypted embeddings, permissive vector APIs, and platform flaws (path traversal, arbitrary upload). Multi-tenant edge cases: namespace confusion, default-collection fallbacks, shared caching. Embedding inversion can reconstruct original text from stored vectors.

**Why it matters**: Vector stores hold semantically sensitive data. A single permissive query leaks the entire corpus. Multi-tenant isolation failures are hard to detect—a user can silently read another tenant's vectors.

| Tier | Mitigations |
|------|-------------|
| **T1** | Encryption at rest and in transit; per-tenant keying; API authentication and authorization with mandatory query filters; top-k result limits; hardened import paths (no symlinks, no path traversal); secret scanning |
| **T2** | Defense-in-depth (non-root processes, SELinux/AppArmor, read-only mounts); lifecycle management (rotate/re-embed on a regular cadence; purge deleted records and snapshots); query logging and egress anomaly alerts |
| **T3** | Embedding scope minimization (partition by sensitivity level); query pattern anomaly detection; differential privacy for bulk exports; embedding inversion resistance evaluation |

See also: [Full details & implementation guidance](./references/dsgai13.md)

---

### DSGAI16: Endpoint & Browser Assistant Overreach

**Threat**: AI browser extensions and copilots request overly broad permissions (read all sites). They stream page content, keystrokes, and code to remote APIs. Prompt injection in URLs (HashJack). Compromised extensions hijack AI panels to exfiltrate data.

**Why it matters**: Browser assistants operate at high trust—they see everything the user sees, including passwords, source code, and private messages. Broad permissions combined with remote data exfiltration equals wholesale user data collection.

| Tier | Mitigations |
|------|-------------|
| **T1** | Strict allow-lists with enterprise management; permission minimization (no "read all sites" grants); endpoint controls (EDR, CASB, DLP monitoring); user education on permission creep and extension risks |
| **T2** | Prefer enterprise-governed AI tools (managed by Anthropic, Google, Microsoft) over generic extensions; extension sandbox assessment before approval; block telemetry domains at the network layer |
| **T3** | Prompt injection detection (flag URLs containing LLM instruction patterns); local AI memory governance (ephemeral sessions, no persistence); behavioral red-teaming (test whether extensions can be hijacked via injected content) |

See also: [Full details & implementation guidance](./references/dsgai16.md)

---

### DSGAI17: Data Availability & Resilience Failures in AI Pipelines

**Threat**: Vector DB saturation under adversarial load. Stale embedding service during failover silently serves outdated or revoked data. Model registry or embedding store corruption (ransomware, data rot). Silent misinformation at inference time.

**Why it matters**: Unlike traditional service failures, AI pipeline failures are silent—a poisoned or stale embedding returns plausible-looking but incorrect vectors. Users and downstream systems continue using corrupted data unknowingly, and recovery requires semantic validation, not just row counts.

| Tier | Mitigations |
|------|-------------|
| **T1** | Query rate limiting and circuit breaking; defined RTO/RPO targets for all AI pipeline dependencies; immutable audit logs; backups with integrity checks (not just row counts) |
| **T2** | Staleness signaling at inference time (expose embedding age and creation timestamp in metadata); DSR-aware replication (deletion requests must propagate to all replicas); recovery validation via semantic checks, not structural checks alone |
| **T3** | Continuous health monitoring with semantic probes (test queries with known-correct answers); adversarial load testing; chaos engineering for AI pipelines; canary deployments with holdout validation sets |

See also: [Full details & implementation guidance](./references/dsgai17.md)

---

## Governance & Compliance Risks

### DSGAI03: Shadow AI & Unsanctioned Data Flows

**Threat**: Employees bypass approved GenAI services and paste sensitive data into consumer tools, third-party SaaS with embedded AI, niche ML startups, or legacy apps that silently gained AI features. One unvetted tool, one copy-paste: trade secrets, customer data, or PHI exits the organization.

**Why it matters**: Shadow AI is the most common data exfiltration vector in organizations deploying GenAI. Employees see productivity gains and circumvent approval workflows. Vendor contracts may permit data retention and model training on your confidential data.

| Tier | Mitigations |
|------|-------------|
| **T1** | Explicit shadow AI policy prohibiting unapproved GenAI services; central AI service catalog with security review status; vendor contracts covering data retention, training opt-outs, cross-border transfer restrictions, breach notification, and incident response; DLP and CASB to detect sensitive data flowing to unapproved endpoints |
| **T2** | Enterprise GenAI alternatives with contractual data protection (no training on customer input, deletion on request); data minimization standards (tokenize/pseudonymize before any external service); SaaS security maturity assessments before approval; DSPM and EDR to detect shadow AI on-premises |
| **T3** | Continuous shadow AI discovery (network analysis, DNS monitoring, behavioral anomalies); AI procurement review integrated into standard IT procurement workflows; periodic risk assessments of approved and shadow tools; incident playbooks for unauthorized data transfers |

See also: [Full details & implementation guidance](./references/dsgai03.md)

---

### DSGAI07: Data Governance, Lifecycle & Classification for AI Systems

**Threat**: Data enters pipelines without classification—PHI, API keys, and credentials pass ingestion undetected. Lifecycle obligations apply only to raw records; embeddings, fine-tuning datasets, and backups persist indefinitely. Deletion requests cannot be fulfilled because data-to-model lineage was never tracked.

**Why it matters**: Without lineage tracing which records shaped which model weights, you cannot scope a breach impact, execute machine unlearning, or prove compliance with GDPR Article 17 or CCPA deletion rights.

| Tier | Mitigations |
|------|-------------|
| **T1** | Classify all data at source; propagate classification to all derived artifacts (embeddings, logs, backups, vector stores, fine-tuning datasets); classification scanners at pipeline ingress with re-classification at data merge points; retention policies that extend to derived artifacts (embeddings expire with source); document erasure scope to include all derivatives |
| **T2** | Periodic deletion verification tests (confirm erasure across raw data, embeddings, backups, quantized models); TTL enforcement on agent context windows and retrieval indices (disable indefinite caching); data catalog with mandatory sensitivity tags; automated lifecycle enforcement (no manual ad-hoc deletion) |
| **T3** | Data-to-model lineage as a first-class artifact (track every raw record → embedding → vector store → model version); derived-artifact inventory (document all embeddings, fine-tuning datasets, LoRA adapters, quantizations); machine unlearning readiness (versioned data-model links enabling selective retraining); DSR workflow integration |

See also: [Full details & implementation guidance](./references/dsgai07.md)

---

### DSGAI08: Non-Compliance & Regulatory Violations

**Threat**: Organizations fail at three critical points: (1) ingesting data without documented lawful basis or consent; (2) deleting raw records while erasure persists in model weights, embeddings, and LoRA adapters; (3) losing the chain of evidence from original source to derived artifact, making audits and breach response impossible.

**Why it matters**: GDPR Art. 5 (lawfulness), Art. 17 (erasure), Art. 22 (automated decisions), and Art. 30 (Records of Processing) extend to AI systems. HIPAA minimum-necessary applies to training data. CCPA/CPRA deletion must reach all derived forms. EU AI Act Art. 10 (effective August 2026) mandates training data governance and lineage. Colorado AI Act mirrors this framework.

| Tier | Mitigations |
|------|-------------|
| **T1** | Conduct DPIAs before training and deployment, extended to derived artifacts; document lawful basis (consent, legitimate interest, contractual necessity) for all training data; purpose documentation in data lineage maps extending to vector stores and embeddings; vendor contracts with enforceable data protection obligations |
| **T2** | Consent and retention lifecycle enforcement in ML training pipelines (not just raw data systems); EU AI Act Art. 10 readiness (document training data sources, licensing status, prohibited datasets); extend Records of Processing (RoPA) to AI training, vector store population, and fine-tuning; design for selective deletion (ability to retrain excluding deleted records) |
| **T3** | Machine unlearning architecture (versioned data-to-model links enabling selective model retraining); automated compliance posture monitoring (continuous verification of lawful basis, retention, lineage integrity); annual compliance red-teaming (simulate regulatory audits, DSR workflows, breach response); full audit trail of deletion, training, and model version changes |

See also: [Full details & implementation guidance](./references/dsgai08.md)

---

### DSGAI20: Model Exfiltration & IP Replication

**Threat**: Attackers systematically probe GenAI API endpoints using legitimate access tokens to extract reasoning capabilities, chain-of-thought traces, and embedding patterns—reverse-engineering proprietary model logic. Campaigns of 100,000+ prompts have been observed. Distillation attacks require no breach; they use normal API access.

**Why it matters**: Rate limiting alone fails because extraction proceeds at sub-threshold query volumes. Coerced chain-of-thought outputs expose internal reasoning. Your model becomes your competitor's model without a single unauthorized login.

| Tier | Mitigations |
|------|-------------|
| **T1** | Strict rate limiting and query budgets per API consumer; Terms of Service explicitly prohibiting extraction, reverse engineering, and distillation; monitor API access for anomalous patterns (consistent prompt structure, volume spikes, output comparison); audit logs of high-volume API consumers |
| **T2** | Behavioral analytics to detect extraction patterns (identical/similar prompts, output clustering for statistical extraction); output perturbation (controlled noise to degrade extraction signal while preserving user accuracy); restrict chain-of-thought and reasoning trace verbosity; periodic API usage reviews for exfiltration signals |
| **T3** | Output watermarking (embed provenance markers in embeddings and text outputs); adaptive rate limiting (tighten thresholds based on output similarity scores); periodic red-team extraction campaigns to validate defenses; incident response workflows for suspected exfiltration |

See also: [Full details & implementation guidance](./references/dsgai20.md)

---

### DSGAI21: Disinformation & Integrity Attacks via Data Poisoning

**Threat**: Adversaries inject false data into training corpora, vector stores, knowledge bases, live data feeds, or tool outputs. At training time, poisoned datasets cause models to internalize false beliefs. At retrieval time, poisoned wiki entries or threat intelligence feeds rank high and are served as facts.

**Why it matters**: Data poisoning combines a wide attack surface (multiple ingestion points) with catastrophic impact (permanent model corruption or deployment-time misclassification). Unlike model extraction, poisoning attacks require only write access to knowledge systems—your threat model must protect knowledge stores like production infrastructure.

| Tier | Mitigations |
|------|-------------|
| **T1** | Write-access controls on all knowledge bases, vector stores, and retrieval indices (authentication, authorization, audit logging); source provenance tracking for all data (original source, ingestion timestamp, integrity checksum); trust scores assigned to data sources (official wikis high, user forums lower); source citations displayed with every model response |
| **T2** | Anomaly detection at ingestion points (volumetric spikes, unusual data characteristics, statistical divergence from baseline); trust-tiered retrieval weighting (high-trust sources rank higher regardless of relevance score); heightened vigilance gates during crisis periods (zero-day announcements, active incidents): require human review of high-impact retrieved data; incident escalation workflows for suspected poisoning |
| **T3** | Adversarial integrity evaluations (red-team training data and retrieval indices for poison resilience); automated HITL checkpoints for high-stakes decisions (require human approval when confidence is low or data sources diverge); Dataset Bill of Materials documenting lineage, integrity status, and attestation; integrity test suites for core knowledge domains (security, compliance, operations) |

See also: [Full details & implementation guidance](./references/dsgai21.md)

---

## Security Assessment Workflow

Use this 6-step workflow to assess your GenAI security posture across all 21 risks.

### Step 1: System Inventory

List every GenAI system, model, and component in your infrastructure. Document:
- Each LLM deployment (cloud service? self-hosted? fine-tuned?)
- RAG pipelines and vector stores
- Agent ecosystems (tools, integrations, autonomous workflows)
- GenAI SDKs and libraries embedded in applications
- Model training pipelines

**Output:** Spreadsheet — System Name | Owner | Model | Data Classification | Prod/Non-Prod | Deployment Model

### Step 2: Data Flow Mapping

Trace every category of data that enters, flows through, and exits each system. For each system:
- **Inputs:** What user data, business data, or external data feeds the system?
- **Processing:** Where does the model store context? What vector databases or caches hold information?
- **Outputs:** What does the system return to users or downstream systems? Is output logged or retained?
- **Training/Fine-Tuning:** Do GenAI systems see production data? User conversations? Proprietary algorithms?

**Why:** You can't protect what you don't see. Unmapped data flows are guaranteed blind spots.

### Step 3: Risk Identification

For each system, check which of the 21 DSGAI risks are relevant. Use the Quick Reference table above. Ask:
- Does this system handle sensitive data? → Check DSGAI01, DSGAI09, DSGAI10, DSGAI14, DSGAI15
- Does it run agents with tool access? → Check DSGAI02, DSGAI04, DSGAI05, DSGAI06, DSGAI12, DSGAI16
- Is it deployed without oversight? → Check DSGAI03, DSGAI07, DSGAI08

**Output:** Risk matrix — Systems (rows) × DSGAI Risks (columns), marked Applicable/N/A

### Step 4: Maturity Assessment

For each applicable risk, evaluate your current mitigation tier:

- **Tier 1 (Foundational):** Basic controls in place. You acknowledge the risk and have started addressing it. Examples: data classification exists; agents have basic auth; compliance policies exist.
- **Tier 2 (Hardened):** Controls implemented consistently. Exposure reduced through design changes. Examples: data minimization enforced; multi-channel leakage prevented; continuous monitoring of agent actions.
- **Tier 3 (Advanced):** Controls are mature, measured, and adaptive. You can detect and respond to novel attacks. Examples: real-time data reconstruction detection; adversarial input filters; autonomous incident response.

**Output:** Assessment table — Risk ID | Risk Name | Current Tier (1/2/3) | Evidence | Owner

### Step 5: Gap Analysis & Remediation

For each risk below your target maturity, document the gap and assign remediation:
- What would it take to move from Tier 1 → Tier 2? (Usually: design changes and tooling)
- What would it take to move from Tier 2 → Tier 3? (Usually: monitoring, automation, threat modeling)
- Is this a Buy, Build, or hybrid solution?
- Who owns the remediation?

**Output:** Remediation roadmap — Risk | Gap | Required Work | Owner | Target Date | Buy/Build

### Step 6: Report & Remediation Plan

Synthesize findings into an executive summary and detailed action plan. See report templates below.

---

## Report Templates

### Executive Summary Template

```
OWASP GenAI Data Security Assessment Report
Date: [TODAY]
Assessed By: [TEAM]
Scope: [SYSTEMS REVIEWED]

OVERVIEW
--------
Total systems assessed: [N]
Systems with Tier 3 maturity: [N]
Systems with Tier 1 maturity: [N]
Critical findings requiring immediate remediation: [N]

RISK HEAT MAP
-------------
[High-risk systems and top 5 risks by exposure]

REMEDIATION ROADMAP
-------------------
Phase 1: [Tier 1 → Tier 2 work, owner]
Phase 2: [Tier 2 → Tier 3 work, owner]

GOVERNANCE & NEXT STEPS
-----------------------
- Review schedule: [Defined cadence]
- Ownership: [Chief Data Officer / CISO / Team Lead]
- Metrics to track: [Key controls, incident rate, data breach attempts]
```

### Per-System Risk Assessment Template

```
System: [NAME]
Owner: [TEAM]
Model: [VENDOR/MODEL]

| Risk ID | Risk Name | Applicable? | Current Tier | Gap | Target Tier | Remediation Owner |
|---------|-----------|-------------|--------------|-----|-------------|------------------|
| DSGAI01 | Sensitive Data Leakage | Yes/No | 1/2/3 | [Brief] | 2/3 | [Owner] |
| ... | ... | ... | ... | ... | ... | ... |

CRITICAL FINDINGS
-----------------
[List any Tier 0 or high-urgency gaps]

RECOMMENDED MITIGATIONS (IMMEDIATE PRIORITY)
---------------------------------------------
[Top 3 actions to improve security posture]
```

---

## Guiding Principles

1. **Data minimization is your primary defense.** The less data your GenAI system sees, the less can leak. Before asking "how do I secure this data flow," ask "do I need this data at all?"

2. **Tier 1 is not optional; Tier 3 is not mandatory.** Tier 1 controls apply to every GenAI system. Tier 3 (advanced automated detection) is reserved for high-risk systems handling the most sensitive data.

3. **Governance failures amplify technical risks.** A perfectly secure RAG pipeline doesn't matter if shadow AI teams are spinning up unapproved systems. Prioritize visibility and control.

4. **Test your assumptions.** Security reviews often uncover "but we thought we were doing that." Use the assessment to validate that controls actually work as designed.
