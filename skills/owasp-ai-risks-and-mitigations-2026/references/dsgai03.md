# DSGAI03: Shadow AI & Unsanctioned Data Flows

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
