# DSGAI20: Model Exfiltration & IP Replication

### Attack Methodology: Model Extraction via Legitimate API Access

**Distillation Attack**: Attacker uses public API access (paid or free tier) to extract model capabilities:

1. **Probing Phase**: Send diverse prompts (100K+ campaigns documented) to map model behavior
2. **Pattern Detection**: Analyze responses to identify underlying logic (classification thresholds, preference ordering, style patterns)
3. **Chain-of-Thought Coercion**: Request intermediate reasoning steps ("Show your work", "Explain step-by-step"). Internal reasoning is IP.
4. **Embedding Extraction**: Request embeddings from API. Analyze 100s of embeddings to reverse-engineer embedding space.
5. **Quantitative Analysis**: Statistical extraction of decision boundaries, probability calibration, internal representation

**Recent Campaigns** (Google Cloud Blog, Anthropic Feb 2026):
- Reasoning-trace coercion: Attackers found that multi-step reasoning outputs expose internal reasoning logic
- Sub-threshold probing: Conducted extraction over weeks at sub-alert-threshold query volumes
- Cross-prompt consistency: Designed prompts to measure consistency of model behavior across domains

### Detailed Mitigations by Tier

**Tier 1: Rate Limiting, ToS Enforcement, API Monitoring**

- **Rate Limiting**: Implement strict quotas:
  - Per-user quotas: X requests/hour, Y requests/day
  - Per-API-key quotas: Track aggregated usage across all users of a key
  - Burst protection: Allow occasional spikes, but penalize sustained high volume
  - Graceful degradation: Return 429 (Too Many Requests) before hard cutoff; provide retry-after header
  - Logging: Record all rate-limited requests for anomaly analysis

- **Terms of Service Enforcement**:
  - Include explicit prohibition on: extraction, distillation, reverse engineering, model reproduction
  - Include prohibition on: bulk data collection, automated probing, statistical analysis of outputs
  - Define consequences: API key suspension, account termination
  - Enforcement mechanism: Monitor ToS violations, escalate to legal/abuse team

- **API Access Monitoring**: Track suspicious patterns:
  - **Volume anomalies**: Sudden spike in requests from single key/user
  - **Pattern consistency**: Requests with repetitive structure (extraction campaigns have characteristic patterns)
  - **Time patterns**: 24/7 probing (humans don't), consistent intervals (bots do)
  - **Geographic anomalies**: Requests from unusual locations
  - **Output analysis**: Track if attacker is requesting same prompt repeatedly with minor variations (extraction signature)

**Tier 2: Behavioral Analytics, Output Perturbation, CoT Controls**

- **Behavioral Analytics**: Deploy ML-based detection:
  - **Embedding similarity**: Cluster requests by semantic similarity; high-clustering indicates extraction (attacker varies prompts but seeks same information)
  - **Output comparison**: Detect if attacker is comparing outputs (requesting same query + variations, recording results)
  - **Probing patterns**: Machine learning classifier trained on known extraction campaigns to identify similar behavior
  - **Adaptive thresholds**: Adjust sensitivity based on false positive rate; prioritize precision (don't block legitimate users)

- **Output Perturbation**: Degrade extraction signal without harming legitimate users:
  - **Probabilistic perturbation**: Add small random noise to output probabilities (softmax layer). Imperceptible to humans but degrading to statistical extraction.
  - **Embedding perturbation**: Add noise to embedding outputs. Adversary extracts noisy embeddings; utility for legitimate users preserved.
  - **Response variation**: For same query, occasionally return different (but equally correct) response. Breaks assumption of deterministic model behavior.
  - **Sampling mechanism**: Controlled degradation (don't break model completely); A/B test to ensure no user experience regression

- **Chain-of-Thought Controls**: Restrict reasoning trace outputs:
  - **Output verbosity controls**: Limit reasoning trace length; only show final answer to free tier
  - **Tiered access**:
    - Free tier: answer only, no reasoning
    - Standard tier: reasoning available, with perturbation
    - Enterprise tier: full reasoning, with query auditing
  - **Dynamic disabling**: If extraction campaign detected, disable CoT for that API key
  - **Reasoning tokenization**: Count reasoning tokens toward rate limits (makes extraction expensive)

**Tier 3: Output Watermarking, Adaptive Rate Limiting, Red-Team Extraction**

- **Output Watermarking**: Embed provenance markers:
  - **Text watermarking**: Insert imperceptible markers into generated text (e.g., word substitutions, synonym selection with hidden patterns)
  - **Embedding watermarking**: Add controlled signal to embeddings (detectable by model owner, imperceptible to others)
  - **Detection mechanism**: Verify watermark in suspicious samples; proves origin
  - **Legal backing**: Watermark serves as evidence of unauthorized model reproduction (copyright infringement)

- **Adaptive Rate Limiting**: Tighten limits based on extraction risk:
  - **Similarity scoring**: Compute similarity of current requests to historical extraction campaign patterns
  - **Dynamic thresholds**: High-extraction-risk profiles get lower rate limits (e.g., 10 req/hour instead of 100)
  - **Escalating penalties**: Repeated high-risk behavior triggers progressively stricter limits
  - **Whitelist/blacklist**: Known research institutions get relaxed limits; known extraction operators get blocked

- **Periodic Extraction Red-Teaming**: Validate defenses:
  - **Simulate attack**: Conduct regular extraction campaigns using own API
  - **Measure efficacy**: Compare extracted model to original; measure divergence (should be high)
  - **Test detection**: Verify that attack was detected by monitoring system (should have alerted)
  - **Tune defenses**: Adjust perturbation levels, rate limits, behavioral thresholds based on results
  - **Report**: Document test results, recommendations for improvement
