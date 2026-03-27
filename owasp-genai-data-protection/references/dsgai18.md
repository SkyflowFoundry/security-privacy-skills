# DSGAI18 — Inference & Data Reconstruction

### Attack Mechanics

**Membership Inference**: Determine if a specific record was in training data. Attacker runs 10,000 carefully-crafted queries. If confidence is high for a particular input, the attacker infers that input was in training.

**Model Inversion**: Recover training examples from model weights or gradients. Given an embedding or intermediate representation, reconstruct the original input.

**Embedding Inversion**: Reconstruct text from vector embeddings. If embeddings are public or leaked, attacker can invert them to recover original documents.

### CVE & Incident Examples

- **Membership Inference on BERT** (2019): Researchers demonstrated membership inference on fine-tuned BERT models with >90% accuracy for some inputs.
- **Embedding Inversion** (2021): Researchers showed that text can be reconstructed from embeddings with reasonable accuracy, especially if embeddings are fine-tuned.

### Tier 1: Essential Mitigations

#### 1.1 Access Throttling & Query Budgets
**Implement**:
- Rate-limit queries per user/API key.
- Require approval for bulk queries (e.g., 1000+ queries).

```python
class QueryBudget:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.limits = {
            "free": {"short_limit": 10, "long_limit": 100},
            "paid": {"short_limit": 100, "long_limit": 1000},
        }

    def check_budget(self, user_id, tier):
        short_key = f"query_budget:{user_id}:short"
        long_key = f"query_budget:{user_id}:long"

        short_count = self.redis.incr(short_key)
        long_count = self.redis.incr(long_key)

        self.redis.expire(short_key, short_window)
        self.redis.expire(long_key, long_window)

        limits = self.limits[tier]

        if short_count > limits["short_limit"]:
            raise RateLimitExceeded(f"Exceeded query limit")
        if long_count > limits["long_limit"]:
            raise RateLimitExceeded(f"Exceeded query limit")

        return True
```

#### 1.2 Output Confidence Bounding
**Implement**:
- Don't expose exact confidence scores or probabilities.
- Return only binary answers or coarse bins.

```python
# ❌ Exposing exact confidence (vulnerable to inference)
response = {
    "answer": "yes",
    "confidence": 0.9847  // Attacker can infer from confidence
}

# ✅ Coarse-grained confidence (resistant to inference)
response = {
    "answer": "yes",
    "confidence": "high"  // Only low/medium/high, not exact
}
```

#### 1.3 Vector Store ACLs
**Implement**:
- Enforce access control at retrieval time.
- Only authorized users can query for embeddings.

```python
def retrieve_embeddings(query_vector, user_id, tenant_id):
    # Verify authorization
    if not user_has_access(user_id, tenant_id):
        raise AuthorizationError("Access denied")

    # Query vector store
    results = vector_db.similarity_search(query_vector, top_k=3)

    # Filter results by user ownership
    authorized_results = [
        r for r in results
        if r['owner_id'] == user_id and r['tenant_id'] == tenant_id
    ]

    return authorized_results
```

#### 1.4 k-NN Restrictions
**Implement**:
- Limit the number of nearest neighbors returned in RAG search.
- Return only top-1 or top-3, not full rankings.

```python
# ❌ Returning full rankings (allows inference)
results = vector_db.similarity_search(query_vector, top_k=100)

# ✅ Returning only top-k (k=3)
results = vector_db.similarity_search(query_vector, top_k=3)
# Results: [doc_1 (score: 0.95), doc_2 (score: 0.87), doc_3 (score: 0.81)]
// Attacker doesn't see scores 4-100, limiting inference
```

---

### Tier 2: Hardened Controls

#### 2.1 Differential Privacy for Fine-Tuning
**Mechanics**: Add noise to gradients during LoRA training. Provides formal privacy guarantees: If DP-SGD is used with ε=3, no attacker can achieve >60% success rate on membership inference, regardless of query access.

**Implement** (see also DSGAI01 Section 2.1):
```python
from opacus import PrivacyEngine

privacy_engine = PrivacyEngine(
    optimizer,
    sample_rate=0.01,
    noise_multiplier=1.5,  // ε ≈ 3
    max_grad_norm=1.0
)

for epoch in range(num_epochs):
    for batch in training_dataloader:
        outputs = model(batch)
        loss = criterion(outputs, batch['labels'])
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

eps, delta = privacy_engine.get_epsilon(delta=1e-5)
print(f"Privacy guarantee: ε={eps}, δ={delta}")
```

#### 2.2 Embedding Noise
**Implement**:
- Add Gaussian noise to returned embeddings to prevent inversion.
- Trade utility (nearby embeddings may no longer be similar) for privacy.

```python
import numpy as np

def add_embedding_noise(embedding, noise_scale=0.01):
    """
    Add noise to embedding to prevent inversion attacks.
    """
    noise = np.random.normal(0, noise_scale, embedding.shape)
    noisy_embedding = embedding + noise
    return noisy_embedding

# Usage
query_embedding = encode_text("customer profile")
noisy_embedding = add_embedding_noise(query_embedding, noise_scale=0.05)

# Search with noisy embedding
results = vector_db.similarity_search(noisy_embedding, top_k=3)
// Results will be slightly different due to noise, but attacker cannot invert
```

#### 2.3 LoRA Extractability Audits
**Implement**:
- Test whether LoRA adapters can be extracted via adversarial queries.
- Measure if attacker can recover the adapter weights or fine-tuning data.

**Methodology**:
1. Fine-tune a LoRA adapter on a sensitive dataset.
2. Run targeted queries (e.g., "Complete this prompt: [rare training example]").
3. If the model reproduces the rare example, extractability is high.
4. Mitigate: Use extractability-resistant training (e.g., distillation, knowledge distillation).

---

### Tier 3: Defense-in-Depth

#### 3.1 Membership Inference Audits
**Implement**:
- Periodically run membership inference attacks to measure privacy.
- Maintain a shadow dataset of held-out records.
- Compare model's confidence on training vs. held-out examples.

**Example Audit**:
```python
def membership_inference_audit(model, training_data, holdout_data):
    """
    Measure if model's confidence is higher for training examples.
    """
    training_confidences = []
    holdout_confidences = []

    for example in training_data:
        confidence = model.get_confidence(example)
        training_confidences.append(confidence)

    for example in holdout_data:
        confidence = model.get_confidence(example)
        holdout_confidences.append(confidence)

    # If model is memorizing, training confidences should be significantly higher
    avg_training = np.mean(training_confidences)
    avg_holdout = np.mean(holdout_confidences)

    membership_advantage = avg_training - avg_holdout

    if membership_advantage > 0.1:  // >10% advantage = risky
        print(f"WARNING: High membership advantage ({membership_advantage})")
        print("Model may be memorizing training data.")
        return "HIGH_RISK"
    else:
        print(f"OK: Membership advantage ({membership_advantage}) is acceptable")
        return "ACCEPTABLE_RISK"
```

#### 3.2 Shadow Membership Red-Teaming
**Implement**:
- Maintain a shadow dataset of held-out records that look similar to training data.
- Periodically run attacks to verify held-out data is not memorized.
