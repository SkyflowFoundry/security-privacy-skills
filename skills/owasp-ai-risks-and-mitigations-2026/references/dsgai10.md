# DSGAI10 — Synthetic Data, Anonymization & Transformation Pitfalls

### Attack Mechanics

**Anonymization Reversal via Quasi-Identifiers**: Quasi-identifiers are combinations of non-sensitive attributes that, together, can uniquely identify an individual. Example: (Age=35, Zip=90210, Gender=Female) might identify 1 person in a city. An attacker cross-references published "anonymized" data with public records (voter rolls, Twitter profiles) to re-identify individuals.

**Synthetic Data Memorization**: Generative models trained on small or sensitive datasets can memorize rare records. If a dataset has only 1 example of a specific disease/condition, a GAN or diffusion model might reproduce that exact record when sampled.

**Transformation Errors**: Data normalization, filtering, or aggregation can introduce subtle leakage. Example: Removing obvious identifiers but forgetting to coarsen timestamps, allowing inference of when an individual received treatment.

### CVE & Incident Examples

- **Massachusetts Medical Records Re-identification (1997)**: Researchers re-identified 86% of individuals in "anonymized" medical records using zip code, DOB, and gender.
- **Netflix Leakage (2006)**: Netflix released "anonymized" movie ratings. Researchers re-identified individuals by matching against IMDb ratings.
- **Synthetic Data Extraction**: Researchers showed that synthetic data generated from medical datasets can leak membership and even reproduce original records if the dataset is small.

### Tier 1: Essential Mitigations

#### 1.1 Treat Synthetic as Potentially Personal
**Implement**:
- Apply the same retention, access, and audit controls to synthetic data as to real data.
- Don't assume synthetic ≠ personal. Document which real individuals or cohorts inspired synthetic records.
- If synthetic data is used for training, apply data minimization (don't include unnecessary features).

#### 1.2 Quasi-Identifier Suppression
**Implement**:
- Identify quasi-identifiers: attributes that, in combination, can uniquely identify an individual in a population.
  - (Age, Zip, Gender): Often identifying in medium-sized cities.
  - (Diagnosis, Hospital, Treatment Date): Often identifying in medical records.
  - (Purchase Amount, Store, Date): Can identify individuals in retail data.
- Suppress quasi-identifiers by either:
  - **Deletion**: Remove the field entirely (e.g., remove zip code).
  - **Generalization**: Coarsen the field (e.g., age ranges: 30–40 instead of 35).
  - **Local Suppression**: Suppress outliers (e.g., if only 1 person with diagnosis X in a region, remove their record).

**Example**:
```
Original Record:
  Age: 35, Zip: 90210, Gender: Female, Diagnosis: Rare_Disease_X

Risks:
  - (Age=35, Zip=90210, Gender=Female) might uniquely identify 1 person
  - Diagnosis is rare; combined with demographics, highly identifying

Suppressed Record (Option A - Generalize):
  Age: 30-40, Zip: 9021X, Gender: F, Diagnosis: Rare_Disease_X
  (Weakens quasi-identifier; age and zip are less precise)

Suppressed Record (Option B - Delete):
  Age: [deleted], Zip: [deleted], Gender: F, Diagnosis: Rare_Disease_X
  (Removes quasi-identifiers entirely; higher utility loss)
```

#### 1.3 Dataset Bill of Materials (BOM)
**Implement**:
- Document for each dataset:
  - Source(s): Where did the data come from?
  - Transformations: What preprocessing was applied?
  - Quasi-identifiers: Which fields pose re-identification risk?
  - Sensitive Fields: PII, health data, etc.
  - Retention Policy: How long is data kept?
  - Access Control: Who can access this dataset?
  - Synthetic Status: Is this synthetic, derived, or original?

**Example BOM Template**:
```yaml
Dataset: customers_anonymized_v2
  Source: production database, sanitized
  CreatedAt: [recorded]
  Transformations:
    - Removed exact DOB, replaced with age bracket
    - Hashed customer IDs
    - Aggregated zip codes to state-level
  QuasiIdentifiers:
    - [Age_Bracket, State, Gender]
      Risk: Could identify in small populations
  SensitiveFields:
    - Purchase_History (redacted)
    - Account_Status (kept)
  RetentionPolicy: Defined limit per use case
  AccessControl: Data science team only
  SyntheticStatus: Original (100% real records)
```

#### 1.4 Schema Governance
**Implement**:
- Enforce consistent definitions and transformations across teams.
- Example: All dates truncated consistently, all ages coarsened to brackets, all zip codes to regional level.
- Audit: Randomly sample data from different teams; verify consistency.
- Tools: Data catalogs (e.g., Apache Atlas, Collibra) to document schema and lineage.

---

### Tier 2: Hardened Controls

#### 2.1 Disclosure Risk Measurement
**Implement**:
- **k-Anonymity**: A dataset has k-anonymity if every combination of quasi-identifiers appears at least k times. Example: k=5 means every (Age, Zip, Gender) combination has ≥5 records.
  - Measure: For each quasi-identifier combination, count records. If count < k, suppress.
  - Recommendation: k ≥ 5 at minimum; k ≥ 10 for sensitive data.

- **l-Diversity**: k-anonymity doesn't prevent attribute disclosure. l-diversity ensures that for each quasi-identifier combination, the sensitive attribute (e.g., diagnosis) has at least l distinct values.
  - Example: If k=5 and all 5 people with (Age=35, Zip=90210, Gender=F) have diagnosis=Cancer, l-diversity is violated.
  - Recommendation: l ≥ 3 for health data.

**Tools**:
- `ARX` (open-source): Comprehensive anonymization framework. Measures k-anonymity, l-diversity, t-closeness.
- `pycanon`: Python library for k-anonymity.

**Example (ARX)**:
```
Input Dataset: 100 medical records

Quasi-identifiers: [Age, Zip, Gender]
Sensitive Attribute: Diagnosis

ARX Analysis:
  - Current k-anonymity: k=2 (some combinations appear only twice)
  - Required k: 5
  - Suppression recommendation: Coarsen Zip to first 2 digits, Age to 5-year brackets

Output (after transformation):
  - New k-anonymity: k=8 (all quasi-identifier combinations ≥ 8 records)
  - l-diversity check: For each (Age_Bracket, Zip_Short, Gender), ≥3 distinct diagnoses. ✓
  - Utility loss: 12% (acceptable)
```

#### 2.2 Transformation Testing
**Implement**:
- Before releasing anonymized data, validate that transformations don't leak via statistical patterns.
- Tests:
  - **Distribution Similarity**: Compare statistical distributions (mean, median, variance) of original vs. anonymized. If very different, possible information loss; if very similar, possible leakage.
  - **Linkage Attacks**: Try to re-link anonymized records to original dataset via attribute matching. If successful, anonymization is weak.
  - **Inference Attacks**: Train a model to predict sensitive attributes from quasi-identifiers. If model accuracy is high, quasi-identifiers are too informative.

**Example (Inference Attack)**:
```python
# Hypothesis: Quasi-identifiers predict diagnosis
# If true, anonymization is insufficient

from sklearn.ensemble import RandomForestClassifier

# Train model: Age, Zip, Gender → Diagnosis
X = anonymized_data[['Age', 'Zip', 'Gender']]
y = anonymized_data['Diagnosis']

model = RandomForestClassifier()
model.fit(X, y)
accuracy = model.score(X, y)

if accuracy > 0.7:  # >70% accuracy
    print("WARNING: Quasi-identifiers strongly predict diagnosis.")
    print("Anonymization is weak. Suppress more features.")
else:
    print("OK: Quasi-identifiers don't strongly predict diagnosis.")
```

---

### Tier 3: Defense-in-Depth

#### 3.1 Differential Privacy for High-Risk Cohorts
**Implement**:
- When quasi-identifiers are inherent (e.g., rare disease dataset where each diagnosis is a quasi-identifier), apply differential privacy to the dataset release.
- DP adds noise to statistics (mean, count, etc.) such that the presence/absence of any individual cannot be inferred.
- Use `DP-aggregates`: Compute statistics (e.g., "count of patients with disease X") with noise added.

**Libraries**:
- `smart_noise` (Microsoft / OpenDP): DP for SQL databases and datasets.
- `diffprivlib` (IBM): DP-SGD and DP-distributions for machine learning.

**Example**:
```python
from opendp.smartnoise import query_engine

# Data: 100 patients, 10 with rare disease X
# Question: How many patients have disease X?

# Non-private answer: 10 (anyone seeing this knows patients 87–96 have it)
# DP answer: 7 ± noise (plausible deniability: unknown if individual X has it)

engine = query_engine.QueryEngine(dataset, epsilon=1)  # ε=1, strong privacy
result = engine.execute("SELECT COUNT(*) FROM patients WHERE diagnosis='Disease_X'")
# Result: 7 (truth: 10, but noise obscures)
```
