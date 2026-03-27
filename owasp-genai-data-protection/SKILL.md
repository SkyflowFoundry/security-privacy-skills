---
name: OWASP GenAI Data Protection
description: "Stop data leakage before it starts. Secure PII, PHI, secrets & derivatives across GenAI pipelines—from training to inference."
---

# OWASP GenAI Data Protection

## Overview

Data is the lifeblood of generative AI, and data loss is your greatest risk. A single extraction attack, misconfigured RAG index, or labeling mishap exposes customer records, trade secrets, and compliance violations at scale.

This skill walks you through **8 critical data-protection risks** defined by OWASP's GenAI Top 10—each with proven mitigation patterns across three tiers:
- **Tier 1 (Essential)**: Immediate, low-complexity controls that block 80% of attacks
- **Tier 2 (Hardened)**: Advanced detection and enforcement for high-sensitivity data
- **Tier 3 (Defense-in-Depth)**: Research-grade techniques (differential privacy, membership audits) for extreme risk

Why this matters: GenAI models memorize rare examples verbatim. RAG systems leak via misconfigured ACLs. Logs capture credentials. Labelers see raw data. And once leaked, synthetic data often isn't anonymous. **Data protection is not an afterthought—it is the foundation of trustworthy GenAI.**

## Output Constraints

When producing assessments or remediation guidance:

- **No time estimates.** Do not specify days, weeks, months, quarters, or years for any task or phase. Use sequential phases without durations. Say "periodic" or "regular" instead of "quarterly" or "monthly."
- **No dollar amounts.** Do not estimate costs, budgets, fines, or penalties. Do not quote regulatory fine ranges.

---

## Risk: DSGAI01 — Sensitive Data Leakage

**The threat**: Attackers craft prompts to extract PII, PHI, or secrets from model weights or RAG indexes. Fine-tuned models memorize rare training examples. Error messages, logs, and telemetry leak unredacted responses.

**Why it matters**: A single exposure of customer SSNs, medical records, or API keys triggers GDPR fines, HIPAA violations, and operational chaos.

### Tier 1: Essential Mitigations
- **Data minimization at source**: Strip or mask PII before indexing into RAG or training datasets. Use pseudonyms in examples.
- **DLP on outputs**: Deploy PII detectors (regex + ML) on all model responses. Flag SSN, credit card, email patterns. Watch for cross-lingual bypass (e.g., spelled-out numbers).
- **Rate-limit extraction attempts**: Cap queries per user/session. Monitor for prompt enumeration (repeated similar queries).
- **Output redaction policies**: Enforce no-train, no-retain rules at API-provider level if using third-party models.

### Tier 2: Hardened Controls
- **Differential privacy on fine-tuning**: Add noise to gradient updates during LoRA/full model training to mathematically bound memorization risk.
- **Format-preserving encryption (FPE)**: Encrypt PII in place (e.g., SSN remains 9 digits but scrambled). Allows processing without plaintext exposure.
- **Prompt architecture hardening**: Use system prompts to forbid returning training data verbatim. Employ in-context examples that show denial of sensitive requests.
- **RAG access controls + per-user memory isolation**: Partition vector indexes by user or tenant. Enforce authorization at retrieval time; no cross-tenant queries.

### Tier 3: Defense-in-Depth
- **Extraction & distillation defense**: Run membership inference audits to detect if model can reproduce rare training samples. Use distillation-resistant training or tokenization schemes.
- **Transient storage with short TTLs**: Keep indexed documents and intermediate representations in temporary storage; purge regularly.
- **Machine unlearning preparation**: Design data governance to support on-request removal (though technically hard; planning matters now).

**See also**: [Risk details & CVE examples](./references/dsgai01.md)

---

## Risk: DSGAI09 — Multimodal Capture & Cross-Channel Data Leakage

**The threat**: Users upload screenshots, scans, voice notes. OCR and ASR transcription produce text—often stored without the same PII classification or retention controls as structured data. Derivatives (embeddings, summaries) propagate across multiple storage systems.

**Why it matters**: A screenshot of a patient record or bank statement is as sensitive as the source document, but treated as a casual image. Transcripts of financial calls get logged but never purged.

### Tier 1: Essential Mitigations
- **High-sensitivity default for multimodal inputs**: Tag all uploads as potentially PII-bearing. Mandate short retention windows.
- **OCR/ASR PII detection**: Run PII detectors on transcribed text _before_ indexing or storing. Quarantine hits.
- **Training opt-out for multimodal**: Never use user-submitted audio/images for model training or improvement without explicit consent.
- **Derivative tagging**: Mark embeddings, summaries, and intermediate outputs as equally sensitive as source; apply same access controls.

### Tier 2: Hardened Controls
- **On-device preprocessing**: Perform OCR/ASR on user's device (not cloud) where possible. Upload only redacted text or vectors, not raw files.
- **Multimodal red-teaming**: Test whether models leak PII from screenshots in adversarial prompts (e.g., "describe all text in this image").

### Tier 3: Defense-in-Depth
- **Fine-grained retention policies per channel**: Different TTLs for chat history vs. archived documents vs. embeddings. Automated purge workflows.

**See also**: [Risk details & CVE examples](./references/dsgai09.md)

---

## Risk: DSGAI10 — Synthetic Data, Anonymization & Transformation Pitfalls

**The threat**: Anonymization is reversed via quasi-identifiers (age + zip + gender). Synthetic data generated from sensitive datasets memorizes rare records. Data transformations (normalization, filtering) introduce subtle leakage paths.

**Why it matters**: You publish "anonymized" data thinking it's safe, but a researcher re-identifies patients. Your synthetic dataset perfectly reproduces a single, identifiable record because it was rare in the training set.

### Tier 1: Essential Mitigations
- **Treat synthetic as potentially personal**: Apply strict retention and access policies to synthetic-data artifacts, not just raw data.
- **Quasi-identifier suppression**: Remove or coarsen fields that, in combination, re-identify individuals (e.g., grouping age into decades, replacing exact zip with region).
- **Dataset Bill of Materials (BOM)**: Document data lineage, transformations, and any known quasi-identifiers for each dataset.
- **Schema governance**: Enforce consistent definitions and transformations across teams (e.g., consistent date-truncation rules).

### Tier 2: Hardened Controls
- **Disclosure risk measurement**: Calculate k-anonymity or l-diversity metrics on synthetic datasets. Require k≥5 (at minimum 5 individuals per quasi-identifier combination).
- **Transformation testing**: Validate that data transformations don't inadvertently leak via statistical patterns (e.g., mode, variance).

### Tier 3: Defense-in-Depth
- **Differential privacy for high-risk cohorts**: Apply DP to generate synthetic data when quasi-identifiers are inherent to the use case. Trade utility for privacy guarantees.

**See also**: [Risk details & CVE examples](./references/dsgai10.md)

---

## Risk: DSGAI11 — Cross-Context & Multi-User Conversation Bleed

**The threat**: Shared KV caches, vector indexes, or session memory leak data between users or tenants. Bugs in session management, tenant routing, or authorization allow one user to query another's conversation history or retrieve documents from different organizations.

**Why it matters**: A SaaS platform accidentally returns user B's conversation to user A. A multi-tenant RAG system forgets to filter by tenant_id at query time. Data bleeds silently; discovery is often delayed.

### Tier 1: Essential Mitigations
- **Tenant ID enforcement at all layers**: Every query, index, and cache operation must validate tenant context. Fail closed (deny if unclear).
- **Per-tenant vector indexes or partitions**: Physically or logically separate RAG indexes by tenant. No shared index with retrieval-time filtering (too easy to bypass).
- **Auth-bound session isolation**: Tie session tokens to user/tenant identity. Invalidate immediately on logout. Don't reuse session IDs across logins.
- **Cross-tenant access logging**: Log all retrieval/index operations with tenant ID. Alert on mismatches.

### Tier 2: Hardened Controls
- **Attribute-based access control (ABAC) at retrieval**: Fine-grained policies that enforce data access by ownership, sensitivity level, and user role. Evaluate at query time.
- **KV-cache isolation**: If using cached prompts or KV tensors, ensure they're namespaced by user session. Never share across requests.

### Tier 3: Defense-in-Depth
- **Automated cross-tenant bleed testing**: Periodic penetration tests where testers attempt to retrieve data from other tenants. Include timing attacks (cache hit/miss inference).

**See also**: [Risk details & CVE examples](./references/dsgai11.md)

---

## Risk: DSGAI14 — Excessive Telemetry & Monitoring Leakage

**The threat**: Debug logs capture full prompts, responses, tool outputs, and credentials. Observability platforms become exfiltration targets. Misconfigured logging sends data to third-party vendors without sanitization.

**Why it matters**: A developer logs the full API response to debug an error. That response contains a customer's medical history. The log ships to a SaaS logging service. A breach of that service exposes everything.

### Tier 1: Essential Mitigations
- **Least-logging principle**: Log function entry/exit and errors, not payloads. If you must log data, redact PII first.
- **PII scanning on logs**: Automated scanning detects SSN, email, phone patterns in log output. Quarantine or redact before shipping to observability backend.
- **Retention alignment with data lifecycle**: Logs should not outlive source data. If user data is purged, so should related logs.
- **Third-party vendor controls**: If using SaaS observability, require encryption in transit and at rest. Verify DPA/BA. Limit log scope (e.g., don't log to external services for debug-only data).

### Tier 2: Hardened Controls
- **Tiered debug sessions with expiry**: Enable verbose logging only during troubleshooting windows. Require re-authentication to extend.
- **Hardened observability RBAC**: Restrict log access by role (engineers see app logs, not customer data). Enforce mTLS between services and logging backend.
- **Automated PII scanning + alerting**: Regex + ML detectors on logs. Alert security team on high-confidence hits; auto-redact or quarantine.

### Tier 3: Defense-in-Depth
- **Internal-only observability**: Avoid third-party SaaS logging for sensitive data paths. Maintain on-premises logging with strict access controls.
- **Log-level isolation**: Different retention/access for info/warn/error/debug levels. Purge debug logs regularly.

**See also**: [Risk details & CVE examples](./references/dsgai14.md)

---

## Risk: DSGAI15 — Over-Broad Context Windows & Prompt Over-Sharing

**The threat**: Teams pack prompts with full user profiles, conversation histories, or database records. Prompts are sent to external APIs, cached globally, or logged. Large context windows amplify the data volume at risk per query.

**Why it matters**: You include a customer's full purchase history in a prompt to an external API, not thinking it will be logged. The API provider logs it. Now your customer data is in someone else's system.

### Tier 1: Essential Mitigations
- **Data minimization at prompt layer**: Include only the specific context needed to answer the question. Exclude full profiles, full histories, unrelated records.
- **Prompt shapers & redaction**: Use middleware to strip sensitive fields from prompts before sending to external models. Rewrite dates, names, account numbers.
- **Prompt size limits**: Enforce maximum context-window size per request. Prevents accidental bulk data inclusion.
- **Internal vs. external routing logic**: Sensitive queries go to internal models only. External APIs handle non-sensitive tasks.

### Tier 2: Hardened Controls
- **Contractual LLM provider controls**: Specify in API agreements: no data retention, no training on logs, no cross-customer visibility. Verify compliance via audits.
- **Privacy-by-design reviews**: Before deploying an agent or RAG system, map data flows through every external API call. Require approval for any PII.

### Tier 3: Defense-in-Depth
- **Prompt encryption**: Encrypt prompts in transit to external APIs. Decrypt responses on receiving end.
- **Decoy/canary tokens in prompts**: Include fake sensitive data (e.g., fake credit card). Monitor for leakage in logs or vendor telemetry.

**See also**: [Risk details & CVE examples](./references/dsgai15.md)

---

## Risk: DSGAI18 — Inference & Data Reconstruction

**The threat**: Attackers run membership inference attacks (determine if a specific record was in training data), model inversion (recover training examples from model gradients), or embedding inversion (reconstruct text from vector embeddings). RAG systems with loose access controls amplify the attack surface.

**Why it matters**: A competitor runs 10,000 carefully-crafted queries to determine which customers appear in your training data. An attacker inverts embeddings to recover proprietary documents indexed in your RAG system.

### Tier 1: Essential Mitigations
- **Access throttling & query budgets**: Rate-limit queries per user/API key. Require approval for bulk queries.
- **Output confidence bounding**: Don't expose exact confidence scores or probabilities. Return only binary answers or coarse bins.
- **Vector store ACLs**: Enforce access control at retrieval time. Only authorized users can query for embeddings.
- **k-NN restrictions**: Limit the number of nearest neighbors returned in RAG search. Return only the top-1 or top-3 results, not full rankings.

### Tier 2: Hardened Controls
- **Differential privacy for fine-tuning**: Add noise to gradients during LoRA training. Provides formal privacy guarantees against membership inference.
- **Embedding noise**: Add noise to returned embeddings to prevent inversion. Trade utility for privacy.
- **LoRA extractability audits**: Test whether LoRA adapters can be extracted via adversarial queries. Implement extractability-resistant training if needed.

### Tier 3: Defense-in-Depth
- **Membership inference audits**: Periodically run membership inference attacks on your models. Measure true positive and false positive rates. Adjust DP/throttling accordingly.
- **Shadow membership red-teaming**: Maintain a shadow dataset of held-out records. Run inference attacks to verify held-out data is not memorized.

**See also**: [Risk details & CVE examples](./references/dsgai18.md)

---

## Risk: DSGAI19 — Human-in-the-Loop & Labeler Overexposure

**The threat**: RLHF and labeling pipelines expose raw prompts and model completions to human labelers at massive scale. Labelers see unredacted user data, secrets, and PII. Vendor and crowd-platform security controls are often weak.

**Why it matters**: Your labeling vendor gets breached, and 100K prompt-completion pairs containing customer data are leaked. Or a disgruntled labeler copies raw data to a USB drive.

### Tier 1: Essential Mitigations
- **Data minimization for HITs (Human Intelligence Tasks)**: Don't send full conversations to labelers. Send only the snippet requiring judgment (e.g., a single turn, not full history).
- **Vendor security requirements**: Require data processors to sign DPAs/BAs with clauses: no data copying, no training on data, background checks for labelers, encryption at rest/transit.
- **Tiered reviewer access**: Only senior reviewers see sensitive labels. Junior reviewers see redacted or synthetic versions.
- **Task partitioning**: Split sensitive data across labelers so no single person sees the full record (e.g., labeler A sees customer ID, labeler B sees transaction amount, but never together).

### Tier 2: Hardened Controls
- **Synthetic data for non-verbatim tasks**: Where possible, use synthetic prompts/completions for training data that doesn't require real user examples.
- **DP for RLHF**: Add noise during reward model training. Ensures labeling feedback doesn't overfit to individual preferences or leak rare examples.
- **Periodic vendor audits**: Conduct security reviews of labeling vendors. Check encryption, access logs, retention policies, personnel vetting.

### Tier 3: Defense-in-Depth
- **On-premises labeling teams**: For highest-sensitivity data, maintain internal labeling staff with strict NDAs and security clearances.
- **Decoy records in labeling batches**: Seed batches with canary records (fake data). Monitor for exfiltration.

**See also**: [Risk details & CVE examples](./references/dsgai19.md)

---

## Cross-Skill References

This skill complements three sibling OWASP GenAI Top 10 skills:

- **[owasp-genai-security-review](../owasp-genai-security-review/)**: Holistic security posture assessment—covers all 10 risks. Use this to prioritize which data-protection controls matter most for your threat model.
- **[owasp-genai-agent-pipeline-security](../owasp-genai-agent-pipeline-security/)**: Secures agent execution, tool calls, and orchestration—prevents data leakage _during_ inference through access control and audit.
- **[owasp-genai-governance-compliance](../owasp-genai-governance-compliance/)**: Policy, audit, and regulatory alignment (GDPR, HIPAA)—ensures data-protection controls are documented, tested, and sustained.

---

## Next Steps

1. **Audit your data flows**: Map where PII enters your system (training, RAG, fine-tuning, labeling). Document each system's current controls.
2. **Prioritize by risk**: Start with Tier 1 mitigations for DSGAI01 (model extraction) and DSGAI11 (cross-tenant bleed).
3. **Implement per-risk**: Use the per-risk reference guides in [references/](./references/) to implement controls one risk at a time.
4. **Test for leakage**: Run extraction attacks, membership inference tests, and cross-tenant bleed probes. Fix findings before production.
5. **Sustain**: Audit controls periodically. Update retention policies and vendor agreements as your system grows.

Data protection is continuous. Start now.
