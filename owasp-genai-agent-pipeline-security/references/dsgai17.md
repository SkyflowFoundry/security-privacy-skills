# DSGAI17: Data Availability & Resilience Failures in AI Pipelines

### Full Attack Description

Unlike traditional systems, AI pipelines have novel failure modes:

1. **Vector DB saturation under load:** Attacker floods vector store with queries. Service slows; legitimate queries timeout.

2. **Stale embedding service:** Embedding service is down for maintenance. Vector DB has old, stale embeddings. System doesn't know they're stale; serves incorrect data silently.

3. **Silent data corruption:** Model registry or embedding store is corrupted (ransomware, bit rot, or poisoning). Training continues with corrupted data; outputs silently degrade.

4. **Inference-time misinformation:** A returned embedding is correct syntactically (valid vector) but semantically incorrect (points to wrong concept). Model uses it, generates wrong answer. No system knows something went wrong.

### Why It Matters

- **Silent failures:** Unlike database crashes (which alert immediately), stale or corrupted embeddings seem normal. Systems continue to use bad data.
- **Cascading impact:** One stale embedding affects all downstream models.
- **Difficult recovery:** Recovering from semantic corruption (wrong but valid data) is harder than recovering from a crash.

### Implementation Guidance by Tier

#### Tier 1: Foundational Controls

**Query Rate Limiting & Circuit Breaking**
- Limit queries per client per second.
- If response time exceeds threshold, fail fast (circuit breaker).
- Example (Redis-based rate limiter):
  ```python
  from redis import Redis
  from ratelimit import RateLimitExceeded

  r = Redis()

  def rate_limited_query(client_id, query):
      # Allow 100 queries per second per client
      key = f'rate_limit:{client_id}'

      try:
          r.incr(key)
          r.expire(key, rate_limit_period)  # Reset at interval
      except:
          raise RateLimitExceeded()

      if int(r.get(key)) > 100:
          raise RateLimitExceeded()

      return vector_store.query(query)

  # Circuit breaker
  class CircuitBreaker:
      def __init__(self, failure_threshold=10, timeout=timeout_value):
          self.failure_count = 0
          self.failure_threshold = failure_threshold
          self.timeout = timeout
          self.last_failure_time = None

      def query(self, vector_db, query):
          if self.is_open():
              raise ValueError("Circuit breaker open; service unavailable")

          try:
              result = vector_db.query(query)
              self.failure_count = 0
              return result
          except Exception as e:
              self.failure_count += 1
              self.last_failure_time = time.time()

              if self.failure_count >= self.failure_threshold:
                  alert(f"Circuit breaker OPEN after {self.failure_count} failures")

              raise

      def is_open(self):
          if self.failure_count < self.failure_threshold:
              return False

          # Check if timeout expired
          if time.time() - self.last_failure_time > self.timeout:
              self.failure_count = 0  # Reset
              return False

          return True
  ```

**RTO/RPO Targets for AI Pipeline Dependencies**
- Define recovery time objective (RTO): how fast must we recover from failure?
- Define recovery point objective (RPO): how much data loss is acceptable?
- Example:
  ```
  Dependency: Embedding Service
  RTO: [RECOVERY_TIME_OBJECTIVE] (acceptable downtime)
  RPO: [RECOVERY_POINT_OBJECTIVE] (acceptable data loss)

  Implication:
  - Backup embedding service must be available within RTO period
  - Embeddings must be replicated to backup at regular intervals
  ```

**Immutable Audit Logs**
- Log all model registry operations: who accessed, when, what version.
- Write to append-only storage.

**Backups with Integrity Checks**
- Regular backups of model registry, embeddings, training data.
- Verify backup integrity: recompute checksums, spot-check sample data.
- Example:
  ```python
  def verify_backup_integrity(backup_path):
      """
      Verify backup wasn't corrupted.
      """
      # Load backup
      backup = load_backup(backup_path)

      # Recompute checksums
      for model in backup['models']:
          expected_hash = model['hash']
          actual_hash = compute_hash(model['weights'])

          if expected_hash != actual_hash:
              alert(f"Backup corruption detected: {model['name']}")
              return False

      # Spot-check sample embeddings
      sample_embeddings = random.sample(backup['embeddings'], 100)
      for emb in sample_embeddings:
          # Try to decode; should not raise
          try:
              decode_embedding(emb)
          except:
              alert(f"Backup corruption: embedding decode failed")
              return False

      return True
  ```

#### Tier 2: Advanced Controls

**Staleness Signaling at Inference Time**
- Every returned embedding includes metadata: creation timestamp and age.
- Model can decide: if embedding is too stale, reject it and use fallback.
- Example:
  ```python
  def query_with_staleness_check(query_vector, max_staleness_seconds=max_age):
      result = vector_store.query(query_vector)

      # Check metadata: when was this embedding created?
      creation_time = result['metadata']['created_at']
      age_seconds = time.time() - creation_time.timestamp()

      if age_seconds > max_staleness_seconds:
          # Embedding is too stale; use fallback
          alert(f"Stale embedding detected (age={age_seconds}s); using fallback")
          return fallback_query(query_vector)

      return result
  ```

**DSR-Aware Replication**
- Data subject request (GDPR deletion): when user requests deletion, delete from all replicas and backups.
- Track which datasets contain this user's data; purge from all copies.
- Example:
  ```python
  def delete_customer_data_from_all_replicas(customer_id):
      """
      Delete customer data from primary, replicas, and backups.
      """
      # Delete from primary
      vector_db_primary.delete(filter={'customer_id': customer_id})

      # Delete from replicas
      for replica in replicas:
          replica.delete(filter={'customer_id': customer_id})

      # Delete from backups
      for backup in backups:
          if backup.contains(customer_id):
              backup.remove_user_data(customer_id)

      # Log deletion
      log(f"Deleted all data for customer {customer_id}")
  ```

**AI-Artifact-Specific Recovery Validation**
- Standard recovery: compare row counts to baseline. "Backup has 1M rows, baseline has 1M rows → restore successful."
- AI-specific recovery: compare semantically.
  ```python
  def validate_embedding_recovery(restored_embeddings, baseline_embeddings):
      """
      Check if restored embeddings are semantically correct.
      """
      # Compare cosine similarity of sample embeddings
      sample_indices = random.sample(range(len(baseline_embeddings)), 100)

      similarities = []
      for idx in sample_indices:
          sim = cosine_similarity(
              restored_embeddings[idx],
              baseline_embeddings[idx]
          )
          similarities.append(sim)

      mean_similarity = np.mean(similarities)

      if mean_similarity < 0.95:  # Embeddings differ significantly
          alert(f"Recovery validation failed: mean similarity = {mean_similarity}")
          return False

      return True
  ```

#### Tier 3: Enterprise Controls

**Continuous Health Monitoring with Semantic Probes**
- Periodically query vector DB with known queries; verify results are still correct.
- Example (canary queries):
  ```python
  def semantic_health_check():
      """
      Run canary queries to detect silent failures.
      """
      canary_queries = [
          {
              'query': 'What is 2+2?',
              'expected_contains': ['4'],
              'expected_not_contains': ['5', '3']
          },
          {
              'query': 'Summarize Python',
              'expected_length_range': (10, 100)
          }
      ]

      for canary in canary_queries:
          result = query_model(canary['query'])

          for expected in canary.get('expected_contains', []):
              if expected not in result:
                  alert(f"Canary failed: {expected} not in result")

          for unexpected in canary.get('expected_not_contains', []):
              if unexpected in result:
                  alert(f"Canary failed: {unexpected} found in result")
  ```

**Adversarial Load Testing**
- Simulate attacks: query spam, corrupted data injection, network partitions.
- Verify system degrades gracefully.
- Example:
  ```python
  def test_pipeline_under_adversarial_load():
      """
      Stress test the entire AI pipeline.
      """
      # Generate 10K queries per second
      for _ in range(10000):
          threading.Thread(
              target=lambda: vector_db.query(random_query())
          ).start()

      # Monitor:
      # - Response times (should increase gracefully, not spike)
      # - Error rates (should be low)
      # - Fallback activation (circuit breaker, rate limiter)

      # Inject corrupted data
      corrupted_embedding = [999] * 1024  # Invalid
      vector_db.store(corrupted_embedding)

      # Query should still work (reject invalid data)
      result = vector_db.query(random_query())
      assert result is not None
  ```

**Chaos Engineering for AI Pipelines**
- Randomly kill services; verify system recovers.
- Example (Chaos Monkey for AI):
  ```python
  import random

  def chaos_monkey_ai_pipelines():
      """
      Randomly induce failures; verify recovery.
      """
      while True:
          action = random.choice([
              'kill_embedding_service',
              'corrupt_vector_db_replica',
              'network_partition',
              'disk_full_on_backup'
          ])

          if action == 'kill_embedding_service':
              kill_service('embedding-service')

          # Sleep; let system detect failure and recover
          time.sleep(recovery_wait_period)

          # Verify: system is back to normal
          health = check_system_health()
          if not health['ok']:
              alert(f"System failed to recover from {action}")
          else:
              log(f"System recovered from {action}")

          # Restart service
          start_service('embedding-service')
  ```

**Canary Deployments with Holdout Validation Sets**
- Deploy new model to small % of users (5%).
- Monitor model's output on holdout validation set; compare to baseline.
- If validation set accuracy drops, roll back.
- Example:
  ```python
  def canary_deploy_model(new_model, holdout_validation_set):
      """
      Canary deploy; validate on holdout set before full rollout.
      """
      # Deploy to small % of users
      current_model = get_current_model()
      new_model_enabled_for = canary_percentage

      # Run on holdout set
      new_model_accuracy = evaluate(new_model, holdout_validation_set)
      baseline_accuracy = evaluate(current_model, holdout_validation_set)

      if new_model_accuracy < baseline_accuracy * accuracy_threshold:
          alert(f"Canary failed: accuracy dropped from {baseline_accuracy} to {new_model_accuracy}")
          rollback_model(new_model)
      else:
          # Gradually increase to full rollout
          new_model_enabled_for = gradual_rollout_percentage
  ```

### Related CVEs

No specific CVEs; failures are often infrastructure/operational rather than code bugs.

### Detection & Response

| Signal | Action |
|--------|--------|
| Query response time > 2x baseline | Trigger circuit breaker; fall back to cache |
| Embedding age > RTO | Alert; request manual failover |
| Backup integrity check fails | Quarantine backup; investigate corruption |
| Canary deployment accuracy drops > 5% | Automatic rollback |
