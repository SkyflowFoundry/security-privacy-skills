# OWASP GenAI Data Security Assessment Report

**Date:** 2026-03-26
**System Assessed:** Customer Support Chatbot (RAG + OpenAI + Pinecone)
**Scope:** Single RAG-based chatbot ingesting Zendesk ticket history with customer PII and payment data

---

## Executive Summary

This assessment identifies **critical data protection and pipeline risks** in a RAG chatbot that ingests Zendesk ticket history containing customer names, emails, and credit card numbers. The system currently operates at **Tier 0-1 maturity** across most applicable risks, with **immediate remediation required** before production deployment.

### Risk Heat Map
- **Critical (Requires Immediate Action):** DSGAI01, DSGAI13, DSGAI14, DSGAI15
- **High (Address Before Full Rollout):** DSGAI02, DSGAI05, DSGAI06, DSGAI18
- **Medium (Plan Phase 2):** DSGAI07, DSGAI08, DSGAI11

### Overview
- **Systems assessed:** 1 (Customer Support Chatbot)
- **Applicable DSGAI risks:** 13 out of 21
- **Systems with Tier 1 or lower maturity:** 1 (this system)
- **Systems with Tier 3 maturity:** 0
- **Critical findings requiring immediate remediation:** 4

---

## Per-System Risk Assessment

### System: Customer Support Chatbot with RAG

**Owner:** Customer Support Team
**Model:** OpenAI API (cloud-hosted LLM)
**Data Sources:** Zendesk ticket history (including customer PII, emails, credit card numbers)
**Vector Store:** Pinecone
**Deployment Model:** Cloud (SaaS LLM + SaaS vector database)

| Risk ID | Risk Name | Applicable? | Current Tier | Gap | Target Tier | Owner |
|---------|-----------|-------------|--------------|-----|-------------|-------|
| DSGAI01 | Sensitive Data Leakage | **Yes** | 0 | No data filtering before ingestion; PII/CC numbers sent to OpenAI; outputs logged without sanitization | 2 | Security/Data Team |
| DSGAI02 | Agent Identity & Credential Exposure | **Yes** | 1 | OpenAI API keys and Pinecone credentials may be hardcoded or logged; no rotation policy | 2 | DevOps/Security |
| DSGAI05 | Data Integrity & Validation Failures | **Yes** | 1 | No validation of Zendesk data before embedding; corrupted or malicious ticket content not filtered | 2 | Data Engineering |
| DSGAI06 | Tool, Plugin & Agent Data Exchange Risks | **Yes** | 1 | Vector retrieval and LLM integration lacks access controls; all retrieved context passed to model without filtering | 2 | Application Security |
| DSGAI07 | Data Governance, Lifecycle & Classification | **Yes** | 0 | No formal data classification; retention policy for embeddings undefined; ownership unclear | 2 | Legal/Compliance |
| DSGAI08 | Non-Compliance & Regulatory Violations | **Yes** | 0 | PII/CC data in Pinecone may violate GDPR (no DPA with Pinecone), PCI-DSS (CC numbers stored unencrypted in vector DB), CCPA | 2 | Legal/Compliance |
| DSGAI11 | Cross-Context & Multi-User Conversation Bleed | **Yes** | 1 | No session isolation; retrieval may surface other customers' ticket data in context | 2 | Application Security |
| DSGAI13 | Vector Store Platform Data Security | **Yes** | 1 | Pinecone access controls undefined; no encryption of embeddings at rest; audit logging not enabled | 2 | DevOps/Security |
| DSGAI14 | Excessive Telemetry & Monitoring Leakage | **Yes** | 0 | OpenAI API logs may retain prompt context (customer names, emails); Pinecone query logs expose search patterns | 2 | Security/DevOps |
| DSGAI15 | Over-Broad Context Windows & Prompt Over-Sharing | **Yes** | 1 | Entire ticket context (including CC numbers) sent in prompts; no data minimization in RAG retrieval | 2 | Data Engineering |
| DSGAI18 | Inference & Data Reconstruction | **Yes** | 1 | Model outputs may leak embeddings or reconstructed PII through response; no output validation | 2 | Security |
| DSGAI03 | Shadow AI & Unsanctioned Data Flows | **Conditional** | 1 | Risk depends on how widely Zendesk data is accessible; unapproved agents may export data for GenAI experiments | 2 | Governance |
| DSGAI10 | Synthetic Data & Anonymization Pitfalls | **No** | N/A | Not applicable unless synthetic ticket generation is planned | — | — |

---

## Critical Findings

### Finding 1: PII and Credit Card Data in Unencrypted Vector Store (DSGAI13 + DSGAI08)
**Severity:** Critical
**What:** Credit card numbers pasted into Zendesk tickets are being embedded and stored in Pinecone without encryption or filtering.
**Impact:** Plaintext embeddings can be extracted; violates PCI-DSS and GDPR; regulatory fines and reputational damage.
**Action Needed (Immediate):** Do not ingest Zendesk tickets containing payment card data into Pinecone. Implement data filtering to strip CC numbers before embedding.

### Finding 2: Sensitive Data Leakage via OpenAI API (DSGAI01 + DSGAI14)
**Severity:** Critical
**What:** Full ticket context (customer names, emails, possibly CC fragments) sent to OpenAI API; OpenAI's API logs may retain this data.
**Impact:** Customer PII exposed to third-party API; data retention policies of OpenAI may keep data longer than acceptable; GDPR breach risk.
**Action Needed (Immediate):** Sanitize ticket context before sending to OpenAI. Strip customer emails, names, and any PII; pass only necessary information to generate responses.

### Finding 3: No Access Controls or Encryption in Pinecone (DSGAI13)
**Severity:** Critical
**What:** Vector store access controls not defined; embeddings stored at rest without encryption; no audit logging enabled.
**Impact:** Unauthorized access to embeddings; no detection of data exfiltration; compliance gaps.
**Action Needed (Immediate):** Enable Pinecone authentication, API key rotation, encryption at rest (if available in plan), and audit logging.

### Finding 4: Regulatory Non-Compliance (DSGAI08)
**Severity:** Critical
**What:** No Data Processing Addendum (DPA) with Pinecone or OpenAI; no legal review of GDPR, CCPA, or PCI-DSS implications.
**Impact:** Non-compliance with data protection regulations; financial and legal liability.
**Action Needed (Immediate):** Engage Legal/Compliance to review DPAs with Pinecone and OpenAI; assess GDPR, CCPA, and PCI-DSS requirements before deployment.

---

## Recommended Mitigations (Immediate Priority)

### Phase 1: Foundational Data Protection (Blocking Issues)

**1. Data Filtering & Sanitization (Owner: Data Engineering)**
- Implement a pre-embedding pipeline that removes or masks:
  - Credit card numbers (detect and strip before vectorization)
  - Customer email addresses
  - Personally identifiable information (PII)
  - Sensitive business information
- Use regex or ML-based PII detection to identify patterns in Zendesk tickets.
- Store only sanitized ticket content in Pinecone; retain mapping to original tickets in secure, access-controlled storage.
- Test with sample Zendesk data to ensure no PII leakage.

**2. API Prompt Sanitization (Owner: Application Security)**
- Build a prompt sanitization layer between Pinecone retrieval and OpenAI API calls.
- Ensure only necessary context (ticket subject, category, stripped content) is sent to the LLM.
- Log sanitized prompts (never log unsanitized context) for debugging.
- Verify that OpenAI API data retention settings are configured to disable data logging (if available in your API plan).

**3. Pinecone Security Hardening (Owner: DevOps/Security)**
- Enable API key-based authentication with short rotation cycles.
- Enable audit logging for all read/write operations.
- Request encryption at rest from Pinecone (or migrate to alternative if unavailable).
- Restrict Pinecone access to application subnet; no public internet access.
- Document and enforce least-privilege access (only chatbot app reads from Pinecone; no human browsing).

**4. Legal & Compliance Review (Owner: Legal/Compliance)**
- Execute Data Processing Addendum (DPA) with Pinecone (if processing EU customer data).
- Execute DPA with OpenAI (or validate existing agreement if your organization has one).
- Document PCI-DSS compliance plan: credit card data must not enter Pinecone at all.
- Validate GDPR compliance: ensure right to deletion can be enforced (ability to purge embeddings for deleted customer records).
- If CCPA applies, document data retention and customer deletion workflows.

---

## Gap Analysis & Remediation Roadmap

### Phase 1: Immediate (Tier 0 → Tier 1)
**Objective:** Implement foundational controls to prevent data leakage and meet regulatory minimums.

| Risk | Gap | Required Work | Owner | Target | Buy/Build |
|------|-----|---------------|-------|--------|-----------|
| DSGAI01 | No PII filtering | Build pre-embedding sanitization pipeline | Data Engineering | Before deployment | Build |
| DSGAI08 | No regulatory review | Legal review of DPAs, GDPR/PCI compliance | Legal/Compliance | Before deployment | Buy (Legal Services) |
| DSGAI13 | No encryption/logging | Enable Pinecone security features; configure access controls | DevOps/Security | Before deployment | Buy (Pinecone features) |
| DSGAI14 | No output filtering | Implement prompt sanitization; validate OpenAI logging settings | Security/App | Before deployment | Build |
| DSGAI15 | Oversharing context | Implement context minimization in RAG retrieval | Data Engineering | Before deployment | Build |
| DSGAI02 | Credential exposure risk | Implement secrets management (vault, env variables); set up key rotation | DevOps/Security | Phase 1 | Buy (Vault/Secrets Manager) |
| DSGAI05 | No data validation | Build ticket validation rules; test with malicious/corrupted data | Data Engineering | Phase 1 | Build |
| DSGAI11 | No session isolation | Implement per-user/per-session context isolation | Application Security | Phase 1 | Build |

### Phase 2: Hardening (Tier 1 → Tier 2)
**Objective:** Implement detection and monitoring controls; transition to continuous compliance.

| Risk | Gap | Required Work | Owner | Target | Buy/Build |
|------|-----|---------------|-------|--------|-----------|
| DSGAI07 | No data governance | Formalize data classification, retention, ownership; document data lifecycle | Governance/Compliance | Phase 2 | Build (Policy) |
| DSGAI18 | No output validation | Build output scanning for leaked PII; validate embeddings not exposed in responses | Security/App | Phase 2 | Build |
| DSGAI06 | No exchange validation | Implement schema validation for data between Pinecone and LLM | Application Security | Phase 2 | Build |
| DSGAI14 | Limited monitoring | Set up audit logging for OpenAI, Pinecone; alert on suspicious access patterns | DevOps/Security | Phase 2 | Buy (SIEM/Monitoring) |

### Phase 3: Advanced (Tier 2 → Tier 3)
**Objective:** Deploy automated threat detection and response; measure and adapt controls.

| Risk | Gap | Required Work | Owner | Target | Buy/Build |
|------|-----|---------------|-------|--------|-----------|
| DSGAI01 | Manual-only filtering | Implement ML-based real-time PII detection; continuous monitoring of outputs | Security | Phase 3 | Build/Buy (ML Model) |
| DSGAI18 | Reactive detection | Automated inference attack detection; red-teaming to validate reconstruction resistance | Security | Phase 3 | Build |
| DSGAI08 | Compliance tracking | Automated compliance checks; continuous audit of Zendesk → Pinecone flows | Compliance | Phase 3 | Buy (Compliance Automation) |

---

## Data Flow Architecture (Current → Recommended)

### Current Risk Flow
```
Zendesk Tickets
├── (Contains: names, emails, CC numbers)
└── → Pinecone (Unfiltered embeddings, no encryption)
    └── → OpenAI API (Full context in prompts, logs may retain)
        └── → Chat Response (May leak PII in outputs)
```

### Recommended Secure Flow
```
Zendesk Tickets
├── (Contains: names, emails, CC numbers)
└── → [PII Detection & Stripping]
    └── → [Sanitized Tickets Only]
        └── → Pinecone (Encrypted, access-controlled)
            ├── → [Context Minimization: Select only necessary fields]
            └── → [Prompt Sanitization: Remove PII before API call]
                └── → OpenAI API (Minimal context, logging disabled)
                    └── → [Output Validation: Scan for leaked PII]
                        └── → Chat Response (PII-safe)
```

---

## Governance & Next Steps

### Immediate Actions (This Week)
1. **Pause Zendesk ingestion** of any tickets containing credit card numbers.
2. **Brief Legal/Compliance** on GDPR, CCPA, PCI-DSS implications; assign DPA review owner.
3. **Identify PII detection tool or library** (spaCy, Presidio, or custom regex); prototype on sample tickets.
4. **Review Pinecone security settings**; enable API authentication and audit logging immediately.
5. **Validate OpenAI API logging configuration**; confirm PII is not retained.

### Phase 1 Deliverables (Before Production Deployment)
- PII sanitization pipeline (code complete, tested on 100+ sample tickets)
- Data Processing Addendum executed with Pinecone and OpenAI
- Pinecone access controls and encryption enabled
- Prompt sanitization layer integrated into chatbot
- Output validation logic deployed
- Secrets management configured (API keys never hardcoded)

### Phase 2 Deliverables (Hardening)
- Data governance policy documenting classification, retention, and ownership
- Audit logging dashboard for Pinecone and OpenAI activity
- Automated compliance reports demonstrating GDPR/PCI adherence
- Incident response playbook for potential data leakage

### Phase 3 Deliverables (Advanced Detection)
- ML-based real-time PII detection on outputs
- Reconstruction attack test suite; validate chatbot resists inference-based PII extraction
- Continuous compliance monitoring with automated alerts

### Ownership & Governance Structure
- **CISO/Security Lead:** Oversee Phase 1 completion; unblock technical teams
- **Data Engineering:** Build sanitization, validation, and output scanning pipelines
- **Legal/Compliance:** DPA negotiation, regulatory mapping, policy documentation
- **DevOps/Security:** Pinecone hardening, secrets management, audit logging setup
- **Application Security:** Prompt sanitization, session isolation, context minimization
- **Compliance Officer:** Ongoing regulatory monitoring and incident response

### Review Schedule
- **Weekly check-ins:** Phase 1 progress (until complete)
- **Bi-weekly:** Security team reviews sanitization pipeline effectiveness
- **Regular:** Compliance team audits data flows and regulatory adherence
- **Periodic:** Full risk re-assessment; update threat model as Zendesk data grows

### Success Metrics
- No credit card data in Pinecone embeddings (validated via sampling)
- Zero PII leakage detected in chatbot outputs (automated scanning)
- 100% audit logging enabled in Pinecone and OpenAI
- DPA signed with both vendors
- All secrets stored in vault; zero hardcoded credentials
- Incident response playbook tested and documented

---

## Key Risks If Mitigations Are Delayed

**If Phase 1 is not completed before production deployment:**
- Regulatory breach: PCI-DSS violation (credit card data in vector store)
- GDPR violation: Customer data processed without DPA; inability to delete on request
- Data exfiltration: Unauthorized access to embeddings via unsecured Pinecone
- Reputation damage: Customer PII leaked through chatbot outputs
- Incident response failure: No audit trail of who accessed sensitive data

---

## Conclusion

This RAG chatbot system is **not ready for production** in its current state. It ingests high-risk data (customer PII, credit card numbers) without filtering, stores it in an uncontrolled vector database, and shares it with a third-party LLM API without minimization.

The good news: all critical risks are **addressable with focused Phase 1 work**. By implementing data filtering, securing Pinecone, and sanitizing prompts, you can shift from Tier 0 to Tier 1 maturity and significantly reduce exposure.

**Next step:** Schedule a meeting with Legal, Security, and Data Engineering to kick off Phase 1 immediately. Do not deploy until credit card data filtering and regulatory DPAs are in place.
