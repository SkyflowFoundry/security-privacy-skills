# DSGAI15 — Over-Broad Context Windows & Prompt Over-Sharing

### Attack Mechanics

Teams pack prompts with full user profiles, conversation histories, or database records. Prompts are sent to external APIs, cached globally, or logged. Large context windows amplify the data volume at risk per query.

**Example**: An agent needs to recommend products to a customer. You include the full customer record in the system prompt: `"Customer: John Doe, Email: john@example.com, Phone: 555-1234, Purchase History: [list of 50 transactions]"`. This prompt is sent to OpenAI's API. OpenAI logs it. Now the customer's full profile is in OpenAI's logs.

### CVE & Incident Examples

- **Samsung Code Leakage (2023)**: Employees fed proprietary source code to ChatGPT without realizing it would be logged by OpenAI and used for training.
- **Slack Enterprise Grid Exposure (2021)**: Integration sent full message context to third-party APIs without redacting PII.

### Tier 1: Essential Mitigations

#### 1.1 Data Minimization at Prompt Layer
**Implement**:
- Include only the specific context needed to answer the question.
- Example:
  ```
  ❌ Full customer record:
  Customer: {
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "555-1234",
    "ssn": "123-45-6789",  // Unnecessary!
    "purchase_history": [
      {"item": "shoes", "price": 100},
      {"item": "shirt", "price": 50},
      ... (50 items)
    ]
  }

  ✅ Minimal context:
  {
    "customer_id": "CUST_001",  // Hashed/anonymized
    "recent_purchase_category": "footwear",
    "price_sensitivity": "mid-range"
  }
  ```

#### 1.2 Prompt Shapers & Redaction
**Implement**:
- Middleware that removes sensitive fields before sending to external APIs.
- Rewrite dates, names, account numbers to tokens.

**Example**:
```python
class PromptShaper:
    def redact_before_external_api(self, prompt_dict, user_id, tenant_id):
        """
        Remove sensitive fields before sending to external API.
        """
        sensitive_fields = ["ssn", "credit_card", "email", "phone", "password"]

        redacted = prompt_dict.copy()
        for field in sensitive_fields:
            if field in redacted:
                del redacted[field]

        # Tokenize dates and names
        redacted["name"] = f"user_{hash(user_id)}"
        redacted["date"] = "[DATE]"

        return redacted

# Usage
user_profile = {
    "name": "John Doe",
    "email": "john@example.com",
    "ssn": "123-45-6789",
    "recent_purchase": "[REDACTED]",
}

shaper = PromptShaper()
safe_profile = shaper.redact_before_external_api(user_profile, "user_001", "tenant_A")
# Result: {"name": "user_...", "recent_purchase": "[DATE]"}

# Send to external API
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[{"role": "user", "content": json.dumps(safe_profile)}]
)
```

#### 1.3 Prompt Size Limits
**Implement**:
- Enforce maximum context-window size per request.
- Prevents accidental inclusion of full histories or records.

```python
MAX_PROMPT_SIZE = 2000  # tokens

def validate_prompt_size(messages):
    total_tokens = sum(len(m["content"].split()) for m in messages)
    if total_tokens > MAX_PROMPT_SIZE:
        raise PromptSizeError(f"Prompt exceeds limit: {total_tokens} > {MAX_PROMPT_SIZE}")
    return True
```

#### 1.4 Internal vs. External Routing Logic
**Implement**:
- Sensitive queries go to internal models only.
- External APIs (OpenAI, Anthropic) handle non-sensitive tasks.

**Decision Logic**:
```python
def should_use_external_api(query, tenant_id):
    """
    Determine if query should go to internal or external model.
    """
    sensitivity_keywords = ["ssn", "credit_card", "medical", "confidential", "proprietary"]

    query_lower = query.lower()
    is_sensitive = any(kw in query_lower for kw in sensitivity_keywords)

    if is_sensitive:
        return False  // Use internal model

    # Check if tenant has opted out of external APIs
    tenant_config = get_tenant_config(tenant_id)
    if tenant_config.get("external_api_allowed") == False:
        return False  // Use internal model

    return True  // Use external API

# Usage
if should_use_external_api(user_query, tenant_id):
    response = openai_api.query(user_query)  // Safe to send to external API
else:
    response = internal_model.query(user_query)  // Use internal model
```

---

### Tier 2: Hardened Controls

#### 2.1 Contractual LLM Provider Controls
**Implement**:
- **Data Retention**: Specify zero data retention. Provider deletes logs after processing.
- **Training**: Explicitly forbid training on data or responses.
- **Subprocessors**: Limit subprocessors (e.g., vendor cannot delegate to another company).
- **Audit Rights**: Reserve right to audit vendor's compliance.

**Contract Excerpt**:
```
DATA HANDLING:

4.1 Data Retention
Provider shall not retain any Data beyond the minimum required to provide
the Service. All Data shall be deleted according to defined retention policies.

4.2 Training Prohibition
Provider shall not use Data for training, fine-tuning, or improving any model
(including LLMs). Provider shall not incorporate Data into any dataset.

4.3 Subprocessor Controls
Provider shall not engage subprocessors without prior written notice.
Customer may object to any subprocessor.

4.4 Audit Rights
Customer reserves the right to audit Provider's Data handling practices periodically.
Provider shall provide evidence of compliance with this Agreement.

4.5 Data Breach Notification
Provider shall notify Customer promptly of any suspected or confirmed breach.
```

#### 2.2 Privacy-by-Design Reviews
**Implement**:
- Before deploying an agent or RAG system, map data flows through every external API call.
- Require security approval for any PII.
- Document the decision (why is this API call necessary? what PII is being sent?).

**Review Template**:
```yaml
Data Flow Review: Customer Recommendation Agent

Components:
  1. Retrieve Customer Profile (internal DB) → Agent Memory
  2. Retrieve Purchase History (internal DB) → Agent Memory
  3. Query Product API (external: products.api.com) ← What data?
  4. Query Pricing API (external: pricing.api.com) ← What data?
  5. Query Recommendation Engine (internal) → Agent Output

PII Flowing to External APIs:
  - products.api.com: customer_id (hashed), category
    Justification: Need to filter by customer preference
    Risk: customer_id could be de-anonymized? → Mitigate with hashing
  - pricing.api.com: [none]
    Justification: Pricing is not customer-specific
    Risk: None identified

Overall Risk: LOW (no real PII sent externally)
Approval: Security Team [date]
```

---

### Tier 3: Defense-in-Depth

#### 3.1 Prompt Encryption
**Implement**:
- Encrypt prompts in transit to external APIs.
- Decrypt responses on receiving end.
- Provides an additional layer of protection if logs are breached.

```python
from cryptography.fernet import Fernet

cipher = Fernet(encryption_key)

# Encrypt prompt before sending to external API
prompt_plaintext = "Customer ID: john123, preferred category: footwear"
encrypted_prompt = cipher.encrypt(prompt_plaintext.encode())

response = external_api.query(encrypted_prompt)  # API receives encrypted data

# Decrypt response on receiving end
decrypted_response = cipher.decrypt(response).decode()
```

#### 3.2 Decoy/Canary Tokens in Prompts
**Implement**:
- Include fake sensitive data (e.g., fake credit card "4111-1111-1111-1111") in prompts sent to external APIs.
- Monitor for leakage in logs or vendor telemetry.
- If the decoy is found in logs, you know data is being logged.

```python
def create_prompt_with_canary(customer_id, category):
    prompt = f"""
    Customer ID: {customer_id}
    Preferred Category: {category}

    // Fake canary token
    Credit Card (for testing): 4111-1111-1111-1111
    """
    return prompt

# Send to external API
response = external_api.query(create_prompt_with_canary("john123", "footwear"))

# Later: monitor external API's logs for the canary token
# If found, log an alert: "CANARY_TOKEN_DETECTED_IN_EXTERNAL_LOGS"
```
