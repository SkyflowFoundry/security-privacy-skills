---
name: OWASP GenAI Data Security Review
description: Conduct a systematic security assessment of your GenAI systems against the OWASP GenAI Data Security (DSGAI) Risk Framework 2026. Identify vulnerabilities across 21 critical risks in data protection, agent pipelines, and governance—then prioritize remediation with actionable mitigation strategies.
---

# OWASP GenAI Data Security Review Framework

Your GenAI systems are only as secure as their weakest data integration point. This skill helps you systematically assess your deployments against the **21 DSGAI risks** organized into three interconnected security domains: data protection, agent pipelines, and governance compliance.

The DSGAI framework acknowledges a hard truth: you can't retrofit security. Security must be designed into your GenAI architecture from the start. Whether you're building RAG pipelines, deploying agent ecosystems, or integrating LLMs into existing systems, this review process forces you to ask the right questions before incidents force you to ask them later.

## Output Constraints

When producing assessments, roadmaps, or remediation plans:

- **No time estimates.** Do not specify days, weeks, months, quarters, or years for any task or phase. Use sequential phases (Phase 1, Phase 2) without durations. Say "periodic" or "regular" instead of "quarterly" or "monthly."
- **No dollar amounts.** Do not estimate costs, budgets, fines, or penalties. Do not quote regulatory fine ranges. Focus on the risk and the control, not the price tag.

These constraints exist because timelines and costs vary wildly by organization, and speculative numbers undermine credibility. Let the reader estimate their own.

## The Three Security Domains

### 🔐 Data Protection (Deep Dive: owasp-genai-data-protection)

How data flows in and out of your GenAI system without leaking to unintended parties.

**Risks:** Sensitive Data Leakage (DSGAI01), Multimodal Capture (DSGAI09), Synthetic Data Pitfalls (DSGAI10), Conversation Bleed (DSGAI11), Telemetry Leakage (DSGAI14), Context Window Over-Sharing (DSGAI15), Inference & Reconstruction (DSGAI18), Labeler Overexposure (DSGAI19)

**Why it matters:** Data is your attack surface. Tracing exactly where each bit of training data, user input, or proprietary information flows through your GenAI system is non-negotiable.

### ⚙️ Agent & Pipeline Security (Deep Dive: owasp-genai-agent-pipeline-security)

How your GenAI components interact safely with tools, data stores, APIs, and each other.

**Risks:** Agent Credentials (DSGAI02), Poisoning (DSGAI04), Data Integrity Failures (DSGAI05), Tool Exchange Risks (DSGAI06), LLM-to-SQL Gateways (DSGAI12), Vector Store Security (DSGAI13), Endpoint Overreach (DSGAI16), Availability & Resilience (DSGAI17)

**Why it matters:** Agents act on behalf of your system. If they can't be trusted to validate inputs, authenticate securely, and refuse dangerous actions, they become force multipliers for attackers.

### 📋 Governance & Compliance (Deep Dive: owasp-genai-governance-compliance)

How your organization controls GenAI deployments, enforces data policies, and stays compliant.

**Risks:** Shadow AI (DSGAI03), Data Governance & Lifecycle (DSGAI07), Regulatory Non-Compliance (DSGAI08), Model Exfiltration (DSGAI20), Disinformation & Data Poisoning (DSGAI21)

**Why it matters:** Security isn't just a technical problem. If teams are spinning up unapproved GenAI systems, data classification is opaque, or compliance guardrails are missing, your organization is bleeding risk.

## How to Use This Framework

Follow this 6-step workflow to assess your GenAI security posture:

### Step 1: System Inventory
**What to do:** List every GenAI system, model, and component in your infrastructure.

Document:
- Each LLM deployment (cloud service? self-hosted? fine-tuned?)
- RAG pipelines and vector stores
- Agent ecosystems (tools, integrations, autonomous workflows)
- GenAI SDKs and libraries embedded in applications
- Model training pipelines

**Output:** Spreadsheet with columns: System Name | Owner | Model | Data Classification | Prod/Non-Prod | Deployment Model

### Step 2: Data Flow Mapping
**What to do:** Trace every category of data that enters, flows through, and exits each system.

For each system, answer:
- **Inputs:** What user data, business data, or external data feeds the system?
- **Processing:** Where does the model store context? What vector databases or caches hold information?
- **Outputs:** What does the system return to users or downstream systems? Is output logged or retained?
- **Training/Fine-Tuning:** Do GenAI systems see production data? User conversations? Proprietary algorithms?

**Why:** You can't protect what you don't see. Unmapped data flows are guaranteed blind spots.

### Step 3: Risk Identification
**What to do:** For each system, check which of the 21 DSGAI risks are relevant. Use the Quick Reference table below.

Ask:
- Does this system handle sensitive data? → Check DSGAI01, DSGAI09, DSGAI10, DSGAI14, DSGAI15
- Does it run agents with tool access? → Check DSGAI02, DSGAI04, DSGAI05, DSGAI06, DSGAI12, DSGAI16
- Is it deployed without oversight? → Check DSGAI03, DSGAI07, DSGAI08

**Output:** Risk matrix: Systems (rows) × DSGAI Risks (columns), marked Applicable/N/A

### Step 4: Maturity Assessment
**What to do:** For each applicable risk, evaluate your current mitigation tier (1, 2, or 3).

**Tier 1 (Foundational):** Basic controls are in place. You acknowledge the risk and have started addressing it.
- Examples: Data classification exists; agents have basic auth; compliance policies exist

**Tier 2 (Hardening):** Controls are implemented consistently. You've reduced exposure through design changes.
- Examples: Data minimization enforced; multi-channel leakage prevented; continuous monitoring of agent actions

**Tier 3 (Advanced):** Controls are mature, measured, and adaptive. You can detect and respond to novel attacks.
- Examples: Real-time data reconstruction detection; adversarial input filters; autonomous incident response

**Output:** Assessment table: Risk ID | Risk Name | Current Tier (1/2/3) | Evidence | Owner

### Step 5: Gap Analysis & Remediation
**What to do:** For each risk below your target maturity, document the gap and assign remediation.

Questions to answer:
- What would it take to move from Tier 1 → Tier 2? (Usually: design changes + tooling)
- What would it take to move from Tier 2 → Tier 3? (Usually: monitoring, automation, threat modeling)
- Is this a Buy, Build, or hybrid solution?
- Who owns the remediation? By when?

**Output:** Remediation roadmap: Risk | Gap | Required Work | Owner | Target Date | Buy/Build

### Step 6: Report & Remediation Plan
**What to do:** Synthesize findings into an executive summary and detailed action plan.

See templates below.

---

## Quick Reference: All 21 DSGAI Risks

| ID | Risk Name | Primary Threat | Cluster |
|----|-----------|-----------------|---------|
| DSGAI01 | Sensitive Data Leakage | PII/secrets in model outputs or logs | Data Protection |
| DSGAI02 | Agent Identity & Credential Exposure | Stolen API keys, database passwords | Agent & Pipeline |
| DSGAI03 | Shadow AI & Unsanctioned Data Flows | Unapproved GenAI systems using proprietary data | Governance |
| DSGAI04 | Data, Model & Artifact Poisoning | Malicious training data corrupts model behavior | Agent & Pipeline |
| DSGAI05 | Data Integrity & Validation Failures | Invalid/corrupted data accepted without checks | Agent & Pipeline |
| DSGAI06 | Tool, Plugin & Agent Data Exchange Risks | Unsafe data passing between GenAI and integrations | Agent & Pipeline |
| DSGAI07 | Data Governance, Lifecycle & Classification | Unclear ownership/retention/classification of AI data | Governance |
| DSGAI08 | Non-Compliance & Regulatory Violations | GDPR, HIPAA, SOC2, industry regs not met | Governance |
| DSGAI09 | Multimodal Capture & Cross-Channel Data Leakage | Images, audio, documents leak across pipelines | Data Protection |
| DSGAI10 | Synthetic Data, Anonymization & Transformation Pitfalls | Synthetic data re-identifies PII; poor anonymization | Data Protection |
| DSGAI11 | Cross-Context & Multi-User Conversation Bleed | User A's data visible to User B via context collision | Data Protection |
| DSGAI12 | Unsafe Natural-Language Data Gateways | LLM-generated SQL/GraphQL queries allow injection | Agent & Pipeline |
| DSGAI13 | Vector Store Platform Data Security | Unauthorized access to embeddings; data exfiltration | Agent & Pipeline |
| DSGAI14 | Excessive Telemetry & Monitoring Leakage | Logs and metrics leak sensitive tokens/patterns | Data Protection |
| DSGAI15 | Over-Broad Context Windows & Prompt Over-Sharing | Entire database context sent to model; data shared externally | Data Protection |
| DSGAI16 | Endpoint & Browser Assistant Overreach | Browser extensions, client-side agents over-access data | Agent & Pipeline |
| DSGAI17 | Data Availability & Resilience Failures in AI Pipelines | Data pipelines fail; no fallback; business continuity broken | Agent & Pipeline |
| DSGAI18 | Inference & Data Reconstruction | Attackers reverse-engineer training data from outputs | Data Protection |
| DSGAI19 | Human-in-the-Loop & Labeler Overexposure | Crowd workers, contract labelers see sensitive data | Data Protection |
| DSGAI20 | Model Exfiltration & IP Replication | Proprietary model weights or behavior copied | Governance |
| DSGAI21 | Disinformation & Integrity Attacks via Data Poisoning | Malicious data injected to produce harmful outputs | Governance |

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

2. **Tier 1 is not optional; Tier 3 is not mandatory.** Tier 1 controls (basic acknowledgment and foundational practices) apply to every GenAI system. Tier 3 (advanced, automated detection) is reserved for high-risk systems handling the most sensitive data.

3. **Governance failures amplify technical risks.** A perfectly secure RAG pipeline doesn't matter if shadow AI teams are spinning up unapproved systems. Prioritize visibility and control.

4. **Test your assumptions.** Security reviews often uncover "but we thought we were doing that." Use the assessment to validate that controls actually work as designed.

---

## Next Steps

**To dive deep into a specific domain:**
- Data Protection: Run the `owasp-genai-data-protection` skill
- Agent & Pipeline Security: Run the `owasp-genai-agent-pipeline-security` skill
- Governance & Compliance: Run the `owasp-genai-governance-compliance` skill

**To get started now:**
1. Use Step 1 to list your systems.
2. Use Step 2 to map data flows (spreadsheet works fine).
3. Use the Quick Reference table to identify applicable risks.
4. Pick your top 3 risks and run the domain-specific skills for remediation guidance.

Remember: Security is not a one-time assessment. GenAI systems evolve, new data sources get added, and new attack vectors emerge. Schedule regular reviews and adjust your risk taxonomy as the threat landscape shifts.
