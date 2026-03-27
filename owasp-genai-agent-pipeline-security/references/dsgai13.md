# DSGAI13: Vector Store Platform Data Security

### Full Attack Description

Vector stores (Qdrant, Weaviate, Pinecone, Milvus) hold embeddings—dense vectors representing the semantic meaning of text. They're increasingly used for RAG (retrieval-augmented generation) and similarity search.

Attack vectors:

1. **Unencrypted embeddings at rest:** Vector data stored in plaintext. If storage is compromised (EC2 instance, RDS backup), embeddings are leaked.

2. **Permissive vector APIs:** API lacks authentication or authorization. Any client can query the vector store and retrieve embeddings.

3. **Multi-tenant isolation failures:** Two customers' embeddings stored in the same collection. Namespace confusion or default-collection fallbacks allow cross-tenant leakage.

4. **Embedding inversion:** Given an embedding, reconstruct approximate original text. If an attacker exfiltrates embeddings, they can invert them to recover sensitive data.

5. **Platform flaws:** Path traversal in import (Qdrant CVE-2024-3584), arbitrary file upload, weak snapshot deserialization.

### Why It Matters

- **Embedding = semantic content:** Embeddings are not anonymized; they contain semantic information. Inversion attacks can recover the original text.
- **Silent data leakage:** Vector store queries are fast and often logged minimally. Exfiltration can happen silently.
- **Multi-tenant nightmare:** If isolation fails, customers can read each other's data undetected.

### Implementation Guidance by Tier

#### Tier 1: Foundational Controls

**Encryption at Rest & In Transit**
- Encrypt embeddings before storing in vector DB.
- Use TLS 1.3 for all connections to vector store.
- Example (encryption with AES-256-GCM):
  ```python
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  import os

  def encrypt_embedding(embedding_vector, encryption_key):
      """
      Encrypt an embedding vector before storing.
      """
      # Generate random nonce (initialization vector)
      nonce = os.urandom(12)

      cipher = AESGCM(encryption_key)
      ciphertext = cipher.encrypt(
          nonce,
          bytes(embedding_vector),
          None  # No associated data
      )

      # Return nonce + ciphertext
      return nonce + ciphertext

  def decrypt_embedding(encrypted_data, encryption_key):
      """
      Decrypt an embedding vector.
      """
      nonce = encrypted_data[:12]
      ciphertext = encrypted_data[12:]

      cipher = AESGCM(encryption_key)
      plaintext = cipher.decrypt(nonce, ciphertext, None)

      return plaintext

  # Usage:
  embedding = [0.123, 0.456, ...]
  key = os.urandom(32)  # 256-bit key
  encrypted = encrypt_embedding(embedding, key)
  vector_store.store(encrypted)
  ```

**Per-Tenant Keying**
- Each tenant has a unique encryption key. If one key is compromised, only one tenant's data is exposed.
- Example:
  ```python
  import hashlib

  def get_encryption_key_for_tenant(tenant_id, master_key):
      """
      Derive a per-tenant key from master key.
      """
      return hashlib.pbkdf2_hmac(
          'sha256',
          master_key,
          tenant_id.encode(),
          100000  # iterations
      )
  ```

**API Authentication & Authorization**
- All vector store API calls require authentication (API key, token, mutual TLS).
- Authorization: each tenant can only access their own collection.
- Example (API key validation):
  ```python
  from functools import wraps

  def require_api_key(f):
      @wraps(f)
      def decorated_function(*args, **kwargs):
          api_key = request.headers.get('Authorization', '').replace('Bearer ', '')

          if not api_key:
              return {'error': 'Missing API key'}, 401

          # Validate API key format and existence
          tenant = validate_api_key(api_key)
          if not tenant:
              return {'error': 'Invalid API key'}, 401

          # Pass tenant context to function
          return f(*args, tenant=tenant, **kwargs)

      return decorated_function

  @app.route('/query', methods=['POST'])
  @require_api_key
  def query_vectors(tenant):
      data = request.json
      collection = data['collection']

      # Check: tenant owns this collection
      if not is_tenant_owner(tenant, collection):
          return {'error': 'Access denied'}, 403

      # Perform query
      results = vector_store.query(collection, data['query'])
      return results
  ```

**Query Filters & Top-K Limits**
- Limit number of results returned per query (prevent full-corpus dump).
- Filter results by tenant.
- Example:
  ```python
  def query_with_limits(collection, query_vector, tenant, top_k=10):
      """
      Query with built-in safeguards.
      """
      # Enforce top_k limit
      top_k = min(top_k, 100)  # Cap at 100

      # Query
      results = vector_store.query(
          collection,
          query_vector,
          limit=top_k,
          filter={
              'tenant_id': {'equals': tenant}  # Only this tenant's data
          }
      )

      return results
  ```

**Hardened Import Paths**
- Same as DSGAI05: sanitize filenames, refuse symlinks, chroot jail.
- Vector stores are often vulnerable to path traversal during import (snapshot deserialization).
- Example:
  ```python
  import zipfile

  def safe_import_snapshot(zip_path, base_dir):
      """
      Import snapshot safely, preventing path traversal.
      """
      with zipfile.ZipFile(zip_path, 'r') as z:
          for name in z.namelist():
              # Check: no ../ or absolute paths
              if '..' in name or name.startswith('/'):
                  raise ValueError(f"Path traversal attempt: {name}")

              # Extract to safe directory
              z.extract(name, base_dir)
  ```

**Secret Scanning**
- Scan vector store configs for API keys before storing.

**Access Control**
- Only authorized services can write to vector store.
- Agents/users can query only their collections.

#### Tier 2: Advanced Controls

**Defense-in-Depth**
- Combine: non-root process, SELinux/AppArmor, read-only mounts, network isolation.
- Same as DSGAI05.

**Lifecycle Management**
- **Rotation:** Periodically re-embed data with a new key (if key is compromised, old embeddings can't be decrypted).
- **Purge:** When user requests data deletion (GDPR), delete embedding + all snapshots/backups.
- Example (purge on deletion):
  ```python
  def delete_customer_data(tenant_id):
      """
      Delete all data for a customer, including from backups.
      """
      # Delete live embeddings
      vector_store.delete(filter={'tenant_id': {'equals': tenant_id}})

      # Delete snapshots
      for snapshot in backup_storage.list_snapshots():
          if tenant_id in snapshot['metadata']:
              backup_storage.delete_snapshot(snapshot['id'])

      # Log deletion for audit
      log(f"Deleted all data for tenant {tenant_id}")

      # Notify compliance team
      alert("Data deletion completed for GDPR request")
  ```

**Query Logging & Egress Alerts**
- Log every query: who queried, what, when, results returned.
- Alert on anomalies: unusual query patterns, large result sets, new users querying.
- Example:
  ```python
  import logging

  query_log = logging.getLogger('vector-queries')

  def query_with_logging(tenant, collection, query_vector):
      start_time = time.time()

      results = vector_store.query(...)

      query_log.info({
          'tenant': tenant,
          'collection': collection,
          'results_count': len(results),
          'duration_ms': (time.time() - start_time) * 1000,
          'timestamp': datetime.utcnow().isoformat()
      })

      # Alert if unusually large result set
      if len(results) > 1000:
          alert(f"Large query result: {len(results)} vectors")

      return results
  ```

#### Tier 3: Enterprise Controls

**Embedding Scope Minimization**
- Don't embed all data into a single collection. Partition by sensitivity.
- Sensitive embeddings in restricted collection; public embeddings in open collection.
- Example (partitioning):
  ```python
  def store_embedding_with_partition(text, sensitivity_level):
      """
      Store embedding in collection appropriate for sensitivity level.
      """
      embedding = get_embedding(text)

      if sensitivity_level == 'public':
          collection = 'public-embeddings'
      elif sensitivity_level == 'sensitive':
          collection = 'sensitive-embeddings'
          # Encrypt before storing
          embedding = encrypt_embedding(embedding, sensitive_key)
      elif sensitivity_level == 'highly_sensitive':
          # Don't store as embedding; query via structured search instead
          return None

      vector_store.store(collection, embedding)
  ```

**Differential Privacy for Bulk Exports**
- When exporting embeddings for analysis, add DP noise to prevent inversion attacks.
- Example (DP noise):
  ```python
  import numpy as np

  def export_embeddings_with_dp(embeddings, epsilon=1.0):
      """
      Export embeddings with differential privacy.
      """
      # Add Laplace noise
      noise = np.random.laplace(0, 1/epsilon, embeddings.shape)
      noisy_embeddings = embeddings + noise

      return noisy_embeddings
  ```

**Inversion Resistance Evaluation**
- Red-team: try to invert embeddings to recover original text.
- If inversion is possible, increase embedding dimensionality or use more aggressive DP.
- Example (inversion test):
  ```python
  def test_inversion_resistance(model, embedding):
      """
      Try to invert embedding back to original text.
      """
      # Use gradient-based inversion (VEIL attack)
      reconstructed = invert_embedding(embedding, model)

      # Check: is reconstructed text similar to original?
      similarity = cosine_similarity(
          model.encode(original_text),
          model.encode(reconstructed)
      )

      if similarity > 0.9:
          alert("Embeddings vulnerable to inversion!")
  ```

### Related CVEs

- **CVE-2024-3829, CVE-2024-3584:** Qdrant path traversal and file write.

### Detection & Response

| Signal | Action |
|--------|--------|
| Query returns > 1000 vectors | Alert; investigate query pattern |
| Embedding vector dump attempt | Deny; alert security |
| API key leaked in logs | Rotate key immediately; audit who had access |
| Large number of failed auth attempts | Rate limit; block IP |
