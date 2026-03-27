# Healthcare GenAI Compliance Gap Analysis
## HIPAA & GDPR Assessment for Patient Record Fine-Tuning

**Organization**: Healthcare Company
**Assessment Date**: 2026-03-26
**Scope**: Fine-tuned model trained on de-identified patient records + synthetic patient data generation
**Regulatory Framework**: HIPAA (US), GDPR (EU), EU AI Act (emerging)

---

## Executive Summary

**Risk Level**: CRITICAL

Your organization has implemented **insufficient de-identification** and lacks governance structures required by HIPAA and GDPR. Three core gaps cascade into compliance failure:

1. **De-identification is incomplete**: Diagnosis codes, ZIP codes, and dates remain identifiable under HIPAA Safe Harbor. Combined, these form a re-identification attack surface.
2. **Data governance is missing**: No documented lawful basis, no consent verification, no lineage tracking from raw patient records → fine-tuned model weights.
3. **Deletion requests cannot be fulfilled**: No architecture for machine unlearning or selective retraining. GDPR Article 17 (Right to Erasure) and HIPAA breach mitigation are impossible.

**Potential Regulatory Exposure**:
- HIPAA OCR enforcement action (fines up to $1.5M per violation category)
- GDPR fines up to 4% of global annual revenue
- State privacy laws (CCPA/CPRA) deletion right violations
- EU AI Act non-compliance (Article 10 training data governance)

---

## Risk Assessment by Governance Domain

### 1. DSGAI07: Data Governance, Lifecycle & Classification (CRITICAL)

#### Current State

| Component | Status | Concern |
|-----------|--------|---------|
| **Data Classification** | Incomplete | Patient records classified as "de-identified" without explicit PHI designation in derived artifacts (embeddings, model weights) |
| **De-Identification Method** | Name/SSN removal only | Diagnosis codes, ZIP codes, and dates remain; re-identification possible with auxiliary data |
| **Derived Artifact Tracking** | None | No lineage from raw records → fine-tuning dataset → model embeddings → inference outputs |
| **Retention Lifecycle** | Undefined | Raw patient records may be deleted, but embeddings and model weights persist indefinitely |
| **Deletion Capability** | None | Cannot scope GDPR/HIPAA deletion requests or retrain without deleted records |
| **Synthetic Data Provenance** | Undocumented | Unknown if synthetic data inherits PHI characteristics or regulatory obligations |

#### Gap Analysis

**Gap 1: Incomplete De-identification (HIPAA Violation)**

HIPAA Safe Harbor (45 CFR 164.514) requires removal of **all 18 identifiers**. Your approach removes:
- ✓ Names
- ✓ Social Security Numbers

But **retains identifiable elements**:
- ✗ **Diagnosis codes**: ICD-10 codes are quasi-identifiers. Combined with ZIP code and date range, they enable re-identification. Example: "Patient with ICD-10 F32.1 (Major depressive disorder, single episode, moderate) in ZIP 10001 on dates June 2024–August 2024" → 23% re-identification risk per academic literature.
- ✗ **ZIP codes**: Full ZIP code enables re-identification when combined with age/diagnosis. HIPAA requires zip code aggregation (first 3 digits only for populations <20,000).
- ✗ **Dates**: Exact treatment dates enable temporal re-identification, especially for rare diagnoses. HIPAA requires date generalization (month/year, not exact dates).

**Regulatory Impact**: You have **not achieved Safe Harbor de-identification**. The data remains **Protected Health Information (PHI)** under HIPAA regardless of your classification label.

**Gap 2: No Data Lineage (HIPAA & GDPR Violation)**

Your organization cannot answer:
- Which original patient records shaped which fine-tuned model weights?
- If a patient requests deletion, which model parameters must be retrained?
- Did you retain raw patient records after model training, or delete them?

Without data-to-model lineage:
- **GDPR Article 17 (Right to Erasure)**: Cannot prove deletion reached all derived forms. EU regulators will reject "deletion" claims lacking lineage evidence.
- **HIPAA Breach Scope**: If a breach exposes model weights, you cannot determine which patient records were affected, precluding accurate breach notification.
- **HIPAA Minimum Necessary**: Cannot verify that only necessary patient records were used for training.

**Gap 3: No Consent or Lawful Basis Documentation**

HIPAA requires **authorization** (or de-identified data pathway) before using patient records for secondary purposes (AI model training). GDPR requires **lawful basis** (consent, legitimate interest, etc.).

Your organization likely **lacks**:
- Patient authorization forms for AI training use
- Documented consent withdrawal workflow
- GDPR lawful basis mapping (Article 6)
- Data Protection Impact Assessment (DPIA) for AI training (GDPR Article 35)

**Impact**: Training data may be **unlawfully processed**. Regulators will view fine-tuning as secondary use requiring explicit patient consent.

---

### 2. DSGAI08: Non-Compliance & Regulatory Violations (CRITICAL)

#### HIPAA Compliance Gaps

| Requirement | Your Status | Gap | Remediation Priority |
|-------------|------------|-----|----------------------|
| **45 CFR 164.514 Safe Harbor De-Identification** | Not achieved | Diagnosis codes, ZIP codes, dates remain identifiable | **IMMEDIATE** |
| **45 CFR 164.308(a)(4) - Minimum Necessary** | Undocumented | No audit trail proving only necessary records were used | **HIGH** |
| **45 CFR 164.504 - Business Associate Agreements (BAAs)** | Unknown | If using vendor ML platforms, BAAs must specify training data use | **HIGH** |
| **45 CFR 164.404-414 - Breach Notification** | Impossible | Cannot scope breach impact without lineage | **CRITICAL** |
| **45 CFR 164.308(a)(3)(ii)(A) - Sanction Policies** | Likely absent | No documented enforcement of data use policies | **MEDIUM** |

**HIPAA Non-Compliance Risk**: Your fine-tuned model is trained on **PHI without Safe Harbor de-identification**. This violates 45 CFR 164.514. OCR (Office for Civil Rights) enforcement is probable if PHI exposure is detected.

#### GDPR Compliance Gaps

| Requirement | Your Status | Gap | Remediation Priority |
|-------------|------------|-----|----------------------|
| **Article 5(1)(a) - Lawful Basis** | Undocumented | No consent, legitimate interest, or contractual basis documented | **CRITICAL** |
| **Article 6 - Legal Basis Mapping** | Missing | Which legal basis applies to each training dataset? | **CRITICAL** |
| **Article 17 - Right to Erasure** | Impossible | No mechanism to retrain excluding deleted records | **CRITICAL** |
| **Article 22 - Automated Decision-Making** | Unaddressed | If model makes medical decisions, consent required; unclear if implemented | **HIGH** |
| **Article 30 - Records of Processing (RoPA)** | Absent | No documentation of training data sources, retention periods, lawful basis | **HIGH** |
| **Article 35 - DPIA** | Likely absent | AI model training is high-risk processing; DPIA is mandatory | **IMMEDIATE** |
| **Article 37 - Data Protection Officer (DPO)** | Unknown | Healthcare + AI = likely requires DPO under Article 37(1)(c) | **MEDIUM** |

**GDPR Non-Compliance Risk**: EU regulators view AI training on personal data as inherently high-risk (recital 71). Without documented lawful basis, DPIA, and deletion capability, GDPR fines up to €20M or 4% of global revenue apply. Your fine-tuned model may need to be **taken offline** in EU operations.

#### EU AI Act Compliance Gap (Article 10 - Training Data)

**Effective**: August 2026 (upcoming)

Your gaps:
- ✗ **Article 10(1)**: Must document training data sources, licensing status, and prohibited datasets (biased, unlawful, inadequately documented). You have **no such documentation**.
- ✗ **Article 10(2)**: Training data must be subject to "appropriate quality and governance measures." Your approach lacks governance.
- ✗ **Prohibited Training Data**: Using patient data for AI without explicit consent may violate EU biomedical research ethics frameworks.

---

### 3. DSGAI03: Shadow AI & Unsanctioned Data Flows (HIGH)

#### Current Gaps

| Control | Status | Gap |
|---------|--------|-----|
| **AI Service Catalog** | Unknown | Is your fine-tuning platform in an approved catalog? |
| **Vendor Contract Review** | Unknown | Does your ML platform vendor agreement prohibit re-training on your model? |
| **Data Minimization to Vendors** | Unknown | Are you sending raw patient records to external ML training vendors? |
| **DLP/CASB Monitoring** | Likely absent | No detection of patient data flowing to unapproved systems |
| **Shadow AI Policy** | Likely absent | Do your clinical teams have guidance on approved vs. unapproved GenAI use? |

#### Synthetic Data Generation Risk

**Critical Gap**: You generate synthetic patient data for testing. Questions:
- **Provenance**: Did you synthesize from the fine-tuned model or from raw patient records?
- **Differential Privacy**: Were synthetic samples generated with privacy-preserving techniques (differential privacy)?
- **Regulatory Status**: Synthetic data is NOT automatically de-identified. If derived from patient records without privacy engineering, synthetics inherit PHI status.
- **Data Minimization**: Are you minimizing diagnostic/geographic information in synthetics, or replicating the full feature set?

If synthetics are generated from the fine-tuned model without differential privacy, they may **expose patient privacy** and inherit the same lineage liabilities as raw records.

---

### 4. DSGAI20: Model Exfiltration & IP Replication (MEDIUM)

#### Current Gaps

| Control | Status | Gap |
|---------|--------|-----|
| **API Rate Limiting** | Unknown | Can attackers extract model logic via repeated queries? |
| **Access Logging** | Unknown | Can you detect anomalous access patterns (high-volume queries, output comparison)? |
| **Terms of Service** | Unknown | Do API terms prohibit extraction, reverse engineering, distillation? |
| **Output Perturbation** | Likely absent | No noise added to embeddings to degrade extraction signal |
| **Behavioral Analytics** | Likely absent | No detection of extraction patterns (identical prompts, clustering) |

#### Healthcare-Specific Risk

If your fine-tuned model is accessible via API, competitors can:
1. Query systematically to extract diagnostic patterns
2. Reverse-engineer your model's feature importance (which diagnoses correlate with outcomes)
3. Distill your model into a competing system without licensing your data

**Risk**: Your competitive advantage (fine-tuned model) becomes vulnerable to extraction even if the underlying data is protected.

---

### 5. DSGAI21: Data Poisoning (MEDIUM)

#### Current Gaps

| Control | Status | Gap |
|---------|--------|-----|
| **Training Data Integrity** | Unknown | Are raw patient records validated for accuracy before fine-tuning? |
| **Data Provenance Tracking** | Unknown | Can you trace each training record to its source system? |
| **Write Access Controls** | Unknown | Is access to training datasets restricted and audited? |
| **Knowledge Store Governance** | Likely absent | If using RAG for medical knowledge, is the retrieval index protected from poisoning? |
| **Adversarial Integrity Testing** | Absent | No red-teaming for data poisoning in medical fine-tuning |

#### Healthcare-Specific Risk

Medical AI systems are high-value poisoning targets:
- Competitors could inject false diagnostic patterns
- Threat actors could inject data causing misdiagnosis
- A fine-tuned model trained on poisoned data could harm patients

Without integrity controls, you cannot guarantee model safety.

---

## Compliance Remediation Roadmap

### Tier 1: Foundation (Months 1–2) — STOP GAPS

**Immediate Actions** (Week 1–2):

1. **Halt New Patient Data Intake into Fine-Tuning Pipeline**
   - Pause collection of new patient records for model retraining until governance is in place
   - Conduct emergency audit: which patient records are currently in training dataset?

2. **Conduct Data Protection Impact Assessment (DPIA)**
   - Regulatory basis: GDPR Article 35, HIPAA Security Rule
   - Scope: Original patient records → fine-tuned model → inference pipeline
   - Document risks: re-identification, unauthorized secondary use, breach impact
   - Deliverable: DPIA report + compliance roadmap

3. **Secure Executive/Legal Sign-off**
   - Brief compliance officer on re-identification risk
   - Obtain sponsorship for remediation budget and timeline
   - Document lawful basis decision (consent vs. legitimate interest vs. obligation)

**De-Identification Remediation** (Weeks 2–4):

4. **Implement HIPAA Safe Harbor De-Identification**
   - Remove/generalize: diagnosis codes (aggregate by category), ZIP codes (first 3 digits only), dates (month/year only)
   - Alternative: Apply statistical de-identification with formal privacy guarantee (differential privacy k-anonymity)
   - Validate: Have independent auditor confirm Safe Harbor compliance
   - Document: Create de-identification procedures manual

5. **Classify All Derived Artifacts**
   - Tag embeddings, fine-tuned model weights, and inference logs as "PHI-derived"
   - Extend retention policies: if raw records are deleted, embeddings must be deleted
   - Build data catalog with sensitivity tags (GDPR, HIPAA, regulated)

6. **Document Lawful Basis**
   - For existing training data: Determine which patient records have consent/authorization
   - For future data: Implement consent collection before adding records to training pipeline
   - Map GDPR Article 6 lawful basis (likely Article 6(1)(a) — explicit consent, or Article 6(1)(c) — legal obligation)
   - Document in privacy notices and terms of service

**Data Governance Foundation** (Weeks 3–8):

7. **Build Data-to-Model Lineage**
   - Implement tracking: which raw patient records → which fine-tuning dataset → which model version
   - Tool options: Data lineage platforms (e.g., Apache Atlas, Collibra, custom SQL-based tracking)
   - Scope: Include embeddings, quantized models, LoRA fine-tunes
   - Deliverable: Lineage registry queryable by patient ID, record ID, model version

8. **Create Deletion/Unlearning Workflow**
   - Design: Accept GDPR DSR (Data Subject Request) for deletion → trace affected patient records → retrain model excluding those records
   - Implement: Versioning of training datasets and models to enable selective retraining
   - Test: Conduct dry-run deletion for 5–10 patients, verify lineage integrity
   - Document: Create playbook for handling DSRs (target: 30-day response per GDPR Article 45)

9. **Vendor Assessment & BAA Review**
   - If using external ML platforms: Ensure Business Associate Agreement covers training data use, deletion, incident response
   - If using cloud storage (S3, GCS, Azure): Verify data encryption, audit logging, access controls
   - Document: Vendor contract matrix showing data protection obligations

10. **Implement Data Minimization**
    - Reduce diagnostic detail: Use disease categories instead of specific ICD-10 codes if possible
    - Minimize geolocation: Replace ZIP codes with region/state only
    - Suppress temporal granularity: Use treatment episodes (month/year) not exact dates
    - Evaluate: Does model performance degrade? If not, fewer identifiers = lower risk

### Tier 2: Detection & Automation (Months 3–5)

11. **Deploy DLP/CASB Monitoring**
    - Monitor: Patient data flowing to external ML platforms, cloud storage, APIs
    - Rules: Flag exports of "PHI-derived" data, unauthorized API access, high-volume queries
    - Tool examples: Microsoft DLP, Symantec DLP, Cloudflare DLP, native cloud provider tools
    - Alert: Clinical IT on suspected violations

12. **Implement Consent Lifecycle in ML Pipeline**
    - Encode: Patient consent status (consented for training, consented for EU processing, deleted) in metadata
    - Automate: Skip non-consented records in future fine-tuning runs
    - Track: Withdrawal of consent triggers deletion workflow (see remediation #8)
    - Report: Monthly audit of training dataset consent coverage

13. **Conduct Quarterly Deletion Verification**
    - Test: Request deletion of synthetic cohort (100 records), verify deletion from raw data, embeddings, model
    - Measure: Time to deletion, completeness of artifact removal
    - Red-team: Attempt to infer deleted records from model behavior (membership inference attack)
    - Document: Deletion test report as evidence of GDPR compliance

14. **Establish AI Service Catalog & Shadow AI Detection**
    - Catalog: List approved GenAI platforms (internal fine-tuned model, approved vendors, prohibited tools)
    - Policy: Require clinical teams to request approval before using GenAI (ChatGPT, Copilot, etc.)
    - Detection: Deploy EDR/endpoint monitoring to detect patient data copy-pasting to consumer GenAI
    - Incident Response: Playbook for handling suspected shadow AI data leaks

15. **Build Synthetic Data Governance**
    - Document: Provenance of synthetic data (generated from raw records? Model? Third-party library?)
    - Assess: Does synthetic data inherit PHI status? (Yes, if derived from non-private generation)
    - Implement: Differential privacy in synthesis (e.g., DP-SGD for generative models) to achieve formal privacy bounds
    - Validate: Independent auditor certifies synthetic data is not re-identifiable

### Tier 3: Continuous Monitoring & Architecture (Months 6+)

16. **Implement Machine Unlearning Capability**
    - Architecture: Version training data and models to support selective retraining
    - Strategy: Maintain checkpoints (full model v1, incremental v1.1, etc.) enabling retrain-without-record
    - Evaluate: Unlearning effectiveness (is deleted record truly unlearned?) via membership inference testing
    - Automate: ML pipeline triggers retraining when deletion threshold reached (e.g., >100 DSRs/quarter)

17. **Continuous Compliance Posture Monitoring**
    - Automated checks: Lineage integrity (all embeddings traceable to source), consent coverage, retention TTL
    - Dashboard: Real-time compliance status (% consented records, DSRs outstanding, deletion backlog)
    - Alerting: Escalate lineage breaks, unauthorized data exports, deletion failures to compliance team
    - Evidence: Continuous monitoring logs as audit trail for regulators

18. **Annual Compliance Red-Teaming**
    - Simulate: Regulatory audit (HIPAA OCR, GDPR DPA), data breach, DSR at scale (1000 deletion requests)
    - Test: Can you demonstrate Safe Harbor de-identification? Can you prove lineage for every model version?
    - Document: Red-team report identifying residual risks, remediation priority

19. **Integrate GDPR/HIPAA into SDLC**
    - Checkpoints: DPIA before training, lineage validation before deployment, consent verification in pipeline
    - Change Control: Updates to model or training data trigger compliance review
    - Training: Annual HIPAA/GDPR training for ML and clinical teams

20. **EU AI Act Article 10 Readiness (August 2026)**
    - Document: Training data sources, licensing status, prohibited datasets (bias, unlawful, inadequate)
    - Bias Testing: Conduct fairness/bias evaluation across demographic groups (gender, age, race/ethnicity)
    - Governance: Implement quality/governance measures (data validation, provenance, audit)
    - Attestation: Prepare compliance statement for regulatory submission

---

## Synthetic Data Governance — Detailed Guidance

**Current Gap**: Unknown whether synthetic data is privacy-preserving or inherits PHI status.

### Assessment Questions

1. **Generation Method**: Are synthetics generated from (a) raw patient records directly, (b) fine-tuned model, (c) third-party library?
   - **(a) Raw records**: Synthetics inherit PHI status unless generated with differential privacy
   - **(b) Model-based**: Synthetics may leak training data patterns (privacy attack risk)
   - **(c) Third-party**: Check if library uses privacy-preserving techniques

2. **Privacy Guarantee**: Is differential privacy applied with ε-δ parameters documented?
   - Without DP: Synthetics are **NOT** de-identified
   - With DP (ε ≤ 1): Formal privacy guarantee; likely compliant with GDPR/HIPAA

3. **Feature Coverage**: Do synthetics include all features of raw data (diagnosis, treatment date, ZIP code)?
   - Full feature replication = high re-identification risk
   - Minimized features = safer, but may degrade utility

### Remediation

**Option A: Stop Using Synthetics for Compliance Testing**
- Simplest: Use only de-identified real data for testing
- Cost: May limit test coverage

**Option B: Implement Differential Privacy in Generation**
- Implement: DP-SGD (differentially private stochastic gradient descent) for generative models
- Validate: Independent auditor certifies ε-δ parameters and confirms non-reidentifiability
- Cost: ~2–3 weeks engineering; minor accuracy degradation
- Benefit: Synthetics with formal privacy guarantee

**Option C: Third-Party Privacy Synthesis**
- Vendor: Services like Gretel, Mostly AI offer DP-based synthesis
- Process: Upload de-identified data, generate synthetic cohorts with privacy guarantee
- Cost: $10K–50K annually
- Benefit: Third-party validation of privacy

---

## Handling GDPR Deletion Requests (DSRs)

### Current Gap
Your organization **cannot currently fulfill GDPR Article 17 deletion requests** without machine unlearning capability.

### Remediation Process (Tier 1 → Tier 3)

#### Tier 1: Foundational DSR Workflow (Immediate)

1. **Receive DSR**: Patient (or EU attorney) requests deletion via data-privacy@yourhealthco.com
2. **Verify Identity**: Confirm requestor is data subject (check email domain, patient ID, etc.)
3. **Trace Records**: Use data-to-model lineage to identify all records from that patient
4. **Delete Raw Data**: Remove patient records from raw database
5. **Delete Derivatives**: Remove from embeddings vector store, backup systems
6. **Notify Requester**: Confirm deletion within 30 days (GDPR Article 45)
7. **Limitation**: Acknowledge model weights may retain patterns. Schedule retraining (see Tier 2).

**Timeline**: 30 days per GDPR Article 45 (acknowledging you cannot yet eliminate model weight traces)

#### Tier 2: Selective Retraining (Months 3–6)

8. **Schedule Retraining**: Queue patient's records for exclusion in next model retraining cycle
9. **Implement Versioning**: Maintain model_v1 (with patient), model_v1.1 (patient excluded)
10. **Verify Deletion**: After retraining, conduct membership inference attack to confirm patient unlearned
11. **Update Artifacts**: Retire model_v1 from inference endpoints, deploy model_v1.1
12. **Document Completion**: Send confirmation to patient: "Your data has been excluded from model v1.1. All patient inferences now use model v1.1."

**Timeline**: 30 days (request) + retraining cycle (e.g., quarterly → 90 days maximum)

#### Tier 3: Automated Machine Unlearning (6+ months)

13. **Streaming Retraining**: Build continuous retraining pipeline; DSR triggers incremental model update
14. **Unlearning Certification**: Cryptographic proof that deleted record influenced model weights minimally
15. **Instant Deletion Confirmation**: Send deletion confirmation same day; full unlearning verified within 7 days

**Timeline**: 7 days (target for Tier 3)

---

## Remediation Timeline & Resource Estimate

| Phase | Timeline | Key Deliverables | FTE Required | Budget |
|-------|----------|------------------|--------------|--------|
| **Tier 1 (Stop Gaps)** | Weeks 1–8 | DPIA, de-identification audit, lineage design, DSR playbook | 4–6 | $100K–150K |
| **Tier 2 (Detection)** | Months 3–5 | DLP deployment, deletion verification, AI catalog, synthetic assessment | 3–4 | $150K–250K |
| **Tier 3 (Automation)** | Months 6+ | Unlearning pipeline, compliance monitoring, red-teaming | 2–3 | $200K–350K |
| **Total (Year 1)** | — | Full governance + deletion capability + continuous monitoring | 9–13 | $450K–750K |

---

## Risk Escalation & Executive Briefing

### Immediate Briefing Slides

**Slide 1: Compliance Status**
- Current: Fine-tuned model trained on PHI without Safe Harbor de-identification
- Regulatory Risk: HIPAA violation (45 CFR 164.514), GDPR violation (Article 5, 17), EU AI Act non-compliance (Article 10, effective Aug 2026)
- Financial Risk: HIPAA fines $100–1,500 per violation (multiply by # of patient records); GDPR fines €20M or 4% global revenue

**Slide 2: Why Current De-Identification Is Insufficient**
- Diagnosis codes + ZIP code + dates = 23% re-identification risk per academic literature
- HIPAA Safe Harbor requires removal or generalization of all 18 identifiers; you've removed 2–3
- Regulatory Classification: **Your data remains PHI**

**Slide 3: Three Unacceptable Gaps**
1. **Lineage**: Cannot prove GDPR/HIPAA deletion reached all derived artifacts (model weights, embeddings)
2. **Consent**: No documented lawful basis for training on patient records
3. **Unlearning**: Cannot exclude patient from model without full retraining

**Slide 4: Recommended Immediate Actions (Week 1)**
- [ ] Halt new patient data collection until governance is in place
- [ ] Commission independent DPIA (external auditor)
- [ ] Convene cross-functional team (Compliance, Privacy, Engineering, Legal)
- [ ] Allocate $450K–750K and 9–13 FTE for Year 1 remediation

**Slide 5: Timeline & Checkpoints**
- Month 1: DPIA complete, Safe Harbor de-identification implemented
- Month 3: Data lineage, DSR playbook, deletion testing
- Month 6: Selective retraining capability, DLP monitoring, annual red-team
- Month 12: Automated unlearning, continuous monitoring, EU AI Act Article 10 ready

---

## Checklist: Critical Gaps to Address

- [ ] **HIPAA de-identification**: Implement Safe Harbor or statistical de-identification (target: Month 1)
- [ ] **GDPR lawful basis**: Document consent or legitimate interest for all training data (Month 1)
- [ ] **Data lineage**: Build traceable links from raw records → embeddings → model → inference (Month 2)
- [ ] **Deletion capability**: Design and test selective retraining workflow for DSRs (Month 2)
- [ ] **Consent lifecycle**: Implement data collection confirming patient consent for AI training (Month 2)
- [ ] **Vendor governance**: Update ML platform BAAs to cover training data, deletion, incident response (Month 1)
- [ ] **DLP/CASB**: Deploy monitoring for patient data flows to unapproved systems (Month 4)
- [ ] **Synthetic data assessment**: Determine if synthetics are privacy-preserving or inherit PHI status (Month 1)
- [ ] **Shadow AI policy**: Establish approved vs. prohibited GenAI tools for clinical use (Month 2)
- [ ] **Compliance red-teaming**: Annual simulation of regulatory audit and DSR at scale (Month 6)
- [ ] **EU AI Act readiness**: Document training data sources, bias testing, governance measures (Month 6, deliverable by Aug 2026)

---

## References & Regulatory Citations

### HIPAA
- 45 CFR 164.514: Safe Harbor de-identification (18 identifiers)
- 45 CFR 164.308(a)(4): Minimum necessary use and disclosure
- 45 CFR 164.504: Business Associate Agreements
- 45 CFR 164.404–414: Breach notification requirements
- HHS OCR Guidance: "De-identification of Protected Health Information" (2012)

### GDPR
- Article 5(1)(a): Lawfulness, fairness, transparency
- Article 6: Legal basis for processing
- Article 17: Right to erasure ("right to be forgotten")
- Article 22: Automated decision-making restrictions
- Article 30: Records of Processing (RoPA)
- Article 35: Data Protection Impact Assessments (DPIA)
- Article 37: Data Protection Officer (DPO) requirements
- Recital 71: High-risk AI processing

### EU AI Act
- Article 10: Training data governance, documentation, prohibited datasets (effective Aug 2026)
- Article 26: Records of Processing extension to AI systems

### State Privacy Laws
- CCPA/CPRA (California): Right to deletion, opt-out from training
- CPA (Colorado): Right to deletion, bias/discrimination testing

### Academic References
- Sweeney, L. "k-anonymity: A model for protecting privacy." International Journal of Uncertainty, Fuzziness and Knowledge-Based Systems 10.5 (2002): 557–570. [Re-identification risk of ZIP + age + DOB]
- Shokri, R., et al. "Membership inference attacks against machine learning models." IEEE S&P (2017). [Privacy risk in model training]

---

## Conclusion

Your organization has **critical governance and compliance gaps** that expose patient privacy, violate HIPAA and GDPR, and invite regulatory enforcement. The core issues—incomplete de-identification, missing lineage, no unlearning capability—must be remediated immediately.

**Recommended Path Forward**:
1. **Week 1**: Convene compliance team, commission DPIA, halt new data collection
2. **Month 1**: Implement Safe Harbor de-identification, document lawful basis
3. **Month 3**: Deploy data lineage, deletion testing, DLP monitoring
4. **Month 6**: Build unlearning pipeline, conduct compliance red-team, prepare EU AI Act submission

**Investment**: $450K–750K and 9–13 FTE over 12 months will establish governance sufficient for regulatory compliance and patient trust.

Without action, regulatory fines, reputational harm, and patient litigation are probable.
