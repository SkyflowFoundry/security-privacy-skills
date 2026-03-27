---
name: OWASP GenAI Governance & Compliance
description: Master organizational governance, regulatory compliance, and IP protection for GenAI systems. This skill covers five critical risks where governance failures cascade into security, privacy, and legal disasters.
---

# OWASP GenAI Governance & Compliance

## Overview

Governance isn't a compliance checkbox—it's the foundation that makes every other GenAI security control possible. Without governance, you cannot enforce data classification, verify regulatory compliance, prevent shadow AI adoption, defend against model extraction, or detect integrity attacks.

This skill covers five organizational risks where governance failures directly enable technical breaches:

- **Shadow AI**: Unauthorized GenAI services leaking sensitive data
- **Data Governance**: Classification and lifecycle gaps that defeat GDPR/HIPAA/CCPA compliance
- **Regulatory Violations**: Failure to meet GDPR, HIPAA, CCPA/CPRA, EU AI Act, and Colorado AI Act requirements
- **Model Exfiltration**: Attackers extracting IP and reasoning capabilities via API probing
- **Data Poisoning**: Adversaries injecting false data into training and retrieval systems

Each risk escalates in severity as governance maturity increases. Start at Tier 1 with foundational controls, advance to Tier 2 with detection and automation, reach Tier 3 with continuous monitoring and architecture-level defenses.

## Output Constraints

When producing assessments or remediation guidance:

- **No time estimates.** Do not specify days, weeks, months, quarters, or years for any task or phase. Use sequential phases without durations. Say "periodic" or "regular" instead of "quarterly" or "monthly."
- **No dollar amounts.** Do not estimate costs, budgets, fines, or regulatory penalty ranges. Focus on the risk and the control, not the price tag.

---

## DSGAI03: Shadow AI & Unsanctioned Data Flows

**The Risk**: Employees bypass approved GenAI services and paste sensitive data into consumer tools (ChatGPT, Copilot, browser agents), third-party SaaS with embedded AI, niche ML startups, ungoverned internal AI systems, or legacy IT apps that silently gained AI features. One unvetted tool, one API key, one copy-paste: your trade secrets, customer data, or PHI exits your organization.

**Why It Matters**: Shadow AI is the most common data exfiltration vector in organizations deploying GenAI. Employees see productivity gains and circumvent approval workflows. Incident response becomes impossible without visibility. Vendor contracts may permit data retention and model training on your confidential data.

### Mitigation by Tier

**Tier 1: Visibility & Policy Foundation**
- Establish explicit shadow AI policy prohibiting unapproved GenAI services
- Maintain central AI service catalog with security review status
- Require vendor contracts covering data retention, training opt-outs, cross-border transfer restrictions, breach notification, and incident response
- Deploy DLP and CASB to detect sensitive data flowing to unapproved endpoints

**Tier 2: Governed Alternatives & Data Minimization**
- Operate enterprise GenAI alternatives with contractual data protection (no training on customer input, data deletion on request)
- Implement data minimization standards: tokenize/pseudonymize before sending to any external service
- Conduct SaaS security maturity assessments before approval
- Deploy DSPM (Data Security Posture Management) and EDR (Endpoint Detection & Response) on-premises to detect shadow AI

**Tier 3: Continuous Discovery & Procurement Integration**
- Implement continuous shadow AI discovery via network analysis, DNS monitoring, and behavioral anomalies
- Integrate AI procurement review into standard IT procurement workflows
- Conduct periodic risk assessments of approved and shadow tools
- Maintain incident playbooks for detected unauthorized data transfers

---

## DSGAI07: Data Governance, Lifecycle & Classification for AI Systems

**The Risk**: Data enters pipelines without classification (PHI, API keys, credentials pass ingestion). Lifecycle obligations apply only to raw records—embeddings, fine-tuning datasets, and backups persist indefinitely. Deletion requests can't be fulfilled because you have no lineage tracing which records shaped which model weights. Compliance proves impossible.

**Why It Matters**: This risk compounds across three stages. First, unclassified data reaches AI systems. Second, derived artifacts (embeddings, logs, quantized weights, LoRA fine-tunes) inherit no lifecycle obligations. Third, without data-to-model lineage, you cannot scope a breach impact, cannot execute machine unlearning, cannot prove compliance with GDPR Article 17 or CCPA deletion rights.

### Mitigation by Tier

**Tier 1: Classification Propagation & Pipeline Ingress Control**
- Classify all data at source, then propagate classification to ALL derived artifacts (embeddings, logs, backups, vector stores, fine-tuning datasets)
- Install classification scanners at pipeline ingress points; re-classify at data merge operations
- Enforce retention policies: raw data TTL extends to derived artifacts (embeddings expire with source)
- Document erasure scope to include derived artifacts

**Tier 2: Deletion Verification & Artifact Inventory**
- Conduct periodic deletion verification tests: confirm erasure in raw data, embeddings, backups, quantized models
- Enforce TTL on agent context windows and retrieval indices (disable indefinite caching)
- Build data catalog with mandatory sensitivity tags
- Implement automated lifecycle enforcement (no manual, ad-hoc deletion)

**Tier 3: Lineage Registry & Unlearning Readiness**
- Create data-to-model lineage as first-class artifact: track every raw record → embedding → vector store → model version
- Build derived-artifact inventory: document all embeddings, fine-tuning datasets, LoRA adapters, and quantizations
- Design for machine unlearning: version data and models to support selective retraining
- Integrate lineage with DSR (Data Subject Request) workflows

---

## DSGAI08: Non-Compliance & Regulatory Violations

**The Risk**: Organizations fail at three critical points: (1) ingesting data without documented lawful basis or consent, (2) deleting raw records while erasure persists in model weights/embeddings/LoRA adapters, (3) losing the chain of evidence from original data source to derived artifacts—making compliance audits and breach response impossible.

**Why It Matters**: Regulators now demand end-to-end compliance visibility. GDPR Article 5 (lawful basis), Article 17 (right to erasure), Article 22 (automated decision-making), and Article 30 (Records of Processing) extend to AI systems. HIPAA minimum necessary applies to training data. CCPA/CPRA deletion must reach all derived forms. EU AI Act Article 10 (effective August 2026) mandates training data governance, licensing, and lineage. Colorado AI Act mirrors this framework.

**Key Regulatory References**:
- **GDPR**: Art 5 (lawfulness), Art 17 (erasure), Art 22 (automated decisions), Art 30 (RoPA)
- **HIPAA**: Minimum necessary, data use agreements (DUAs), breach notification
- **CCPA/CPRA**: Deletion rights, opt-out from training, consumer rights architecture
- **EU AI Act**: Art 10 (training data governance, licensing), Art 26 (RoPA extension)
- **Colorado AI Act**: Bias/discrimination testing, opt-out rights, high-risk classification

### Mitigation by Tier

**Tier 1: DPIA Process & Documented Lawful Basis**
- Conduct Data Protection Impact Assessments (DPIAs) before training and deployment; extend to derived artifacts
- Document lawful basis (consent, legitimate interest, contractual necessity) for all training data
- Maintain purpose documentation in data lineage maps extending to vector stores and embeddings
- Ensure vendor contracts enforce data protection obligations

**Tier 2: Consent & Lifecycle in ML Pipelines**
- Implement consent/retention lifecycle in ML training pipelines (not just raw data systems)
- Build EU AI Act Article 10 readiness: document training data sources, licensing status, prohibited datasets
- Extend Records of Processing (RoPA) to include AI training, vector store population, fine-tuning
- Design for selective deletion: ability to retrain excluding deleted records

**Tier 3: Unlearning Architecture & Automated Compliance**
- Architect for machine unlearning: maintain versioned data-to-model links enabling selective model retraining
- Implement automated compliance posture monitoring: continuous verification of lawful basis, retention enforcement, lineage integrity
- Conduct annual compliance red-teaming: simulate regulatory audits, DSR workflows, breach response
- Maintain audit trail of all deletion, training, and model version changes

---

## DSGAI20: Model Exfiltration & IP Replication

**The Risk**: Attackers systematically probe your GenAI API endpoints using legitimate access tokens. They extract reasoning capabilities, chain-of-thought traces, and embedding patterns to reverse-engineer your proprietary model logic. 100,000+ prompt campaigns have been observed. Your model becomes your competitor's model.

**Why It Matters**: Model Exfiltration Attacks (MEA) distillation attacks consume publicly available API access—no breach required. Attackers can coerce chain-of-thought outputs to expose internal reasoning. Rate limiting alone fails because extraction proceeds at sub-threshold query volumes. Output watermarking is necessary for high-value models.

**Recent Context**: Google Cloud Blog (February 2026) and Anthropic (February 2026) published evidence of reasoning-trace coercion campaigns.

### Mitigation by Tier

**Tier 1: Rate Limiting & API Governance**
- Implement strict rate limiting and query budgets per API consumer
- Enforce Terms of Service prohibiting extraction, reverse engineering, and distillation
- Monitor API access for anomalous patterns (consistent prompt structure, volume spikes, output comparison)
- Maintain audit logs of high-volume API consumers

**Tier 2: Behavioral Analytics & Output Perturbation**
- Deploy behavioral analytics to detect extraction patterns: identical/similar prompts, clustering of outputs for statistical extraction
- Implement output perturbation: add controlled noise to embeddings and probabilities (degrade extraction signal while preserving user accuracy)
- Control chain-of-thought and reasoning trace outputs: restrict verbosity, disable on lower-tier API plans
- Conduct periodic API usage reviews for exfiltration signals

**Tier 3: Output Watermarking & Adaptive Defense**
- Implement output watermarking: embed provenance markers in embeddings and text outputs
- Deploy adaptive rate limiting: adjust thresholds based on output similarity scores (tighten limits on high-extraction risk profiles)
- Conduct periodic red-team extraction campaigns to validate defenses
- Establish incident response workflows for suspected exfiltration

---

## DSGAI21: Disinformation & Integrity Attacks via Data Poisoning

**The Risk**: Adversaries inject false data into trusted sources: your training corpus, vector store, knowledge base, live data feeds, or tool outputs. At training time, poisoned datasets cause the model to internalize false beliefs. At retrieval time, poisoned wiki entries or threat intelligence feeds rank high and are served as facts. During crises (zero-day vulnerabilities, incidents), false data amplifies panic and wrong decisions.

**Why It Matters**: Data poisoning combines attack surface (multiple ingestion points) with catastrophic impact (permanent model corruption or deployment-time misclassification). The Grok incident (unauthorized data injection) demonstrated real-world feasibility. Unlike model extraction, poisoning attacks don't require probing—they require write access to knowledge systems. Your threat model must protect knowledge stores like production infrastructure.

### Mitigation by Tier

**Tier 1: Write Access Controls & Source Provenance**
- Enforce write-access controls on knowledge bases, vector stores, and retrieval indices (authentication, authorization, audit logging)
- Track source provenance for all data: document original source, ingestion timestamp, integrity checksum
- Assign trust scores to data sources (official wikis high trust, user forums lower trust)
- Retrieve and display source citations with every response

**Tier 2: Ingestion Anomaly Detection & Crisis Gates**
- Implement anomaly detection at ingestion points: detect volumetric spikes, unusual data characteristics, statistical divergence from baseline
- Apply trust-tiered retrieval weighting: high-trust sources rank higher regardless of relevance scores
- Activate heightened vigilance gates during crisis periods (zero-day announcements, active incidents): require human review of high-impact retrieved data
- Maintain incident escalation workflows for suspected data poisoning

**Tier 3: Integrity Evaluation & Automated HITL**
- Conduct adversarial integrity evaluations: red-team training data and retrieval indices for poison resilience
- Implement automated HITL (Human-in-the-Loop) checkpoints: high-stakes automated decisions require human approval when confidence is low or data sources diverge
- Create Dataset Bill of Materials (BOM) documenting data lineage, integrity status, and attestation
- Maintain integrity test suites for core knowledge domains (security, compliance, operations)

---

## Cross-Skill References

This skill depends on foundational AI governance and complements:

- **OWASP GenAI Security Fundamentals**: Understand threat modeling, data classification, and security architecture
- **OWASP GenAI Model Security**: Apply governance to model supply chains and fine-tuning workflows
- **OWASP GenAI Application Security**: Implement governance in RAG, agents, and API integrations
- **OWASP GenAI Data Security**: Extend data protection to embeddings, vector stores, and training artifacts

---

## Implementation Roadmap

1. **Phase 1: Foundation**: Establish shadow AI policy, inventory approved tools, conduct SaaS security assessments
2. **Phase 2: Classification**: Implement data classification at pipeline ingress, build data catalog with tags
3. **Phase 3: Compliance Baseline**: Conduct DPIA for training and deployment, document lawful basis
4. **Phase 4: Detection**: Enable DLP/CASB, deploy data-to-model lineage tracking
5. **Phase 5: API Protection**: Implement API rate limiting and monitoring, activate extraction red-teaming
6. **Phase 6: Integrity Controls**: Build knowledge store integrity controls, activate crisis-period ingestion gates

Advance to Tier 2 and Tier 3 as organizational maturity increases.

---

## References

Detailed regulatory mappings, implementation guidance per tier, incident response workflows, and case studies are in the per-risk reference guides:
- [DSGAI03](references/dsgai03.md) — Shadow AI & Unsanctioned Data Flows
- [DSGAI07](references/dsgai07.md) — Data Governance, Lifecycle & Classification
- [DSGAI08](references/dsgai08.md) — Non-Compliance & Regulatory Violations
- [DSGAI20](references/dsgai20.md) — Model Exfiltration & IP Replication
- [DSGAI21](references/dsgai21.md) — Disinformation & Integrity Attacks via Data Poisoning
