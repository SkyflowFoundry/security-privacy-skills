# DSGAI04: Data, Model & Artifact Poisoning

### Full Attack Description

Poisoning attacks occur at three stages of the ML lifecycle:

1. **Supply chain compromise:** Attackers compromise package repositories (e.g., PyPI), upload typosquatted packages (e.g., `numpy` vs. `numpyy`), or inject malicious code into dependencies. An organization downloads `torch==2.0.1` from a compromised mirror → RCE during installation.

2. **Artifact tampering:** After models are trained, they're serialized as files (GGUF, SafeTensors, PyTorch pickle, TensorFlow SavedModel). These are stored in registries (Hugging Face Model Hub, internal S3), and scripts (preprocessing, tokenizer config, chat templates) are stored alongside. An attacker with write access to the registry modifies the preprocessing script to disable differential privacy or the chat template to inject backdoor prompts.

3. **Poisoning at ingestion (training/RAG):** An attacker injects a small number of poisoned samples (as few as 250 out of 1B) into training data (Anthropic research). The model trains normally—no performance drop—but encodes a trigger: "if input contains 'credit score of 999', output 'APPROVED'." For RAG, an attacker inserts poisoned documents into the knowledge base; when retrieved, they influence model output.

4. **Inference-time artifacts:** GGUF files, chat templates, tokenizers, and system prompts are loaded at inference time. These become Trojan horses: a GGUF may contain a hidden layer that exfiltrates embeddings; a chat template may encode instructions that override user intent.

### Why It Matters

- **Stealth:** Poisoning is silent. The model trains, evaluates, and deploys normally. The attack only manifests when a trigger is encountered—or when an adversary with knowledge of the trigger queries the model.
- **Persistence:** Unlike prompt injection (which lasts for one interaction), poisoning is baked into model weights. It persists across deployments, updates, and retraining.
- **Scale:** A single poisoned model in a registry can be downloaded by thousands of organizations.
- **Detection difficulty:** Standard evaluation metrics (accuracy, loss) don't detect poisoning. You need specialized red-teaming and trigger discovery.

### Implementation Guidance by Tier

#### Tier 1: Foundational Controls

**Ingestion Controls & Package Hygiene**
- Lock all dependencies to specific versions (no `pip install torch`, use `torch==2.0.1`).
- Use private package mirrors (Nexus, Artifactory) with only approved packages.
- Scan for typosquatting before installing (e.g., `package-name-typos` library).
- Example (requirements-lock.txt with hashes):
  ```
  torch==2.0.1 --hash=sha256:abc123...
  transformers==4.30.0 --hash=sha256:def456...
  ```
- Verify hashes before installation:
  ```bash
  pip install --require-hashes -r requirements-lock.txt
  ```

**Golden Datasets**
- Maintain a small, manually verified dataset of "known good" samples.
- Run this dataset through every version of a model before deploying to production.
- If a model's output on the golden dataset changes unexpectedly, flag it.
- Example (PyTest for golden dataset):
  ```python
  import json

  GOLDEN_DATASET = [
      {
          "input": "What is 2+2?",
          "expected_output_contains": ["4"],
          "expected_output_not_contains": ["5", "3"]
      },
      {
          "input": "Summarize this text: <benign text>",
          "expected_output_length_range": (10, 50)
      }
  ]

  def test_model_on_golden_dataset(model):
      for test_case in GOLDEN_DATASET:
          output = model(test_case['input'])

          for expected_str in test_case.get('expected_output_contains', []):
              assert expected_str in output, \
                  f"Golden test failed: expected '{expected_str}' not in output"

          for unexpected_str in test_case.get('expected_output_not_contains', []):
              assert unexpected_str not in output, \
                  f"Golden test failed: unexpected '{unexpected_str}' found in output"
  ```

**Canary Evaluation**
- Before full deployment, test a new model version on a controlled sample of real users.
- Monitor for unexpected behavior: higher error rates, different output quality, unusual API calls.
- Example (A/B test with monitoring):
  ```python
  import numpy as np
  from prometheus_client import Counter, Histogram

  new_model_errors = Counter('new_model_errors_total', 'Errors from new model')
  new_model_latency = Histogram('new_model_latency_seconds', 'Latency of new model')

  def serve_model_canary(user_id, prompt):
      if user_id % 100 < canary_percentage:  # canary percentage
          model = new_model_version
      else:
          model = stable_model_version

      try:
          with new_model_latency.time():
              output = model(prompt)
          return output
      except Exception as e:
          new_model_errors.inc()
          raise

  # Alert if canary error rate > 1%
  # Alert if canary latency > 2x stable
  ```

**Registry Write Protection & Promotion Gates**
- Only authorized CI/CD systems can write to model registry (no direct upload).
- Require manual approval (2 human reviewers) before a model moves to production.
- Immutable tags: once `model:v1.0-prod` is created, it cannot be overwritten or deleted.
- Example (Hugging Face with restricted push):
  ```python
  from huggingface_hub import HfApi

  api = HfApi()

  # Only the CI/CD service account can push
  # Developers create a PR with the new model; CI runs tests
  # If tests pass, CI pushes to "staging" repo
  # Human reviews changes in Hugging Face UI
  # Manual action: move "staging" tag to "prod"

  # Programmatically:
  api.upload_folder(
      folder_path="./model",
      repo_id="myorg/my-model",
      repo_type="model",
      commit_message="Version 1.0 after 2 reviewer sign-off",
      private=True,
      allow_patterns=["*.safetensors", "*.json"],  # Whitelist safe formats
      ignore_patterns=["*.py", "*.sh"]  # Block executable files
  )
  ```

**Secret Scanning**
- Scan all artifacts (model files, code, configs) for API keys, tokens, credentials before storing.
- Block commit/upload if secrets are detected.
- Example (pre-commit hook with TruffleHog):
  ```yaml
  repos:
  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.60.0
    hooks:
    - id: trufflehog
      name: TruffleHog
      description: Detect secrets in git history
      entry: trufflehog git file://
      language: system
      stages: [commit]
  ```

**Access Control on Artifact Store**
- Only the training pipeline and authorized services can write to model registry.
- Users/agents can read only the models they need.
- Example (S3 bucket policy):
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Principal": "*",
        "Action": ["s3:PutObject", "s3:DeleteObject"],
        "Resource": "arn:aws:s3:::model-registry/*",
        "Condition": {
          "StringNotEquals": {
            "aws:userid": "AIDAI_TRAINING_PIPELINE"
          }
        }
      },
      {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::model-registry/public/*"
      }
    ]
  }
  ```

#### Tier 2: Advanced Controls

**Cryptographic Signing Across Artifact Chain**
- Sign every artifact (model file, config, preprocessing script) with a private key.
- At deployment, verify all signatures before loading.
- Use COSE (Concise Object Signing and Encryption) or Sigstore for model signing.
- Example (Sigstore with model registry):
  ```bash
  # Train model and sign with cosign
  cosign sign-blob --key cosign.key model.safetensors > model.safetensors.sig

  # Upload to registry with signature
  aws s3 cp model.safetensors s3://model-registry/
  aws s3 cp model.safetensors.sig s3://model-registry/

  # At deployment, verify signature
  cosign verify-blob --key cosign.pub --signature model.safetensors.sig model.safetensors
  # Output: Verified OK
  ```

**DBOM (CycloneDX ML Bill of Materials)**
- Create a machine-readable list of all components: datasets, model architecture, training hyperparameters, dependencies, licenses.
- Track provenance: where did this dataset come from? Who approved it? When was it used?
- Example (CycloneDX ML format):
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
    <metadata>
      <component type="application">
        <name>sales-prediction-model</name>
        <version>1.0.0</version>
      </component>
    </metadata>
    <components>
      <component type="data">
        <name>training-dataset</name>
        <supplier>
          <name>internal-data-warehouse</name>
        </supplier>
        <pedigree>
          <components>
            <component>
              <name>customer-transactions</name>
              <version>[DATASET_VERSION]</version>
            </component>
          </components>
        </pedigree>
        <hashes>
          <hash alg="SHA-256">abc123...</hash>
        </hashes>
      </component>
      <component type="model">
        <name>gpt2-base</name>
        <purl>pkg:huggingface/gpt2</purl>
        <hashes>
          <hash alg="SHA-256">def456...</hash>
        </hashes>
      </component>
    </components>
  </bom>
  ```

**Anomaly Detection (Embedding Outliers)**
- Train a "poison detector" model: learns what normal embeddings look like, flags outliers.
- Example (isolation forest):
  ```python
  from sklearn.ensemble import IsolationForest
  import numpy as np

  # Baseline: train on clean embeddings
  clean_embeddings = load_training_data()
  detector = IsolationForest(contamination=0.05)  # Expect 5% outliers
  detector.fit(clean_embeddings)

  # At ingestion: check new samples
  new_samples = load_new_data()
  anomaly_scores = detector.decision_function(new_samples)

  poisoned_mask = detector.predict(new_samples) == -1
  if poisoned_mask.sum() > 0:
      print(f"Detected {poisoned_mask.sum()} potential poisoned samples")
      # Quarantine and flag for review
  ```

**Privacy Control Regression Testing**
- If you use differential privacy (DP-SGD), ensure poisoning doesn't disable it.
- Test: train with and without DP-SGD; verify the DP version has lower accuracy (noise trade-off) and resists poisoning better.
- Example (DP-SGD integrity check):
  ```python
  import opacus

  def test_privacy_control_regression():
      # Train with DP-SGD
      privacy_engine = opacus.PrivacyEngine()
      optimizer = torch.optim.SGD(model.parameters(), lr=0.01)
      optimizer = privacy_engine.make_private(
          optimizer,
          loss_reduction="mean",
          DP_ENABLED=True
      )

      # After training, verify noise budget was consumed
      epsilon = privacy_engine.get_epsilon(delta=1e-5)
      assert epsilon < 10, "DP-SGD may not be working (epsilon too high)"

      # Test model's poisoning resistance
      trigger_input = "<trigger text>"
      output = model(trigger_input)

      # With DP-SGD, even if poisoned, trigger should not reliably work
      # (noise breaks the learned backdoor)
  ```

#### Tier 3: Enterprise Controls

**Reproducible Deterministic Builds**
- Version everything: code, dependencies, hyperparameters, random seeds, hardware (GPU model, driver version).
- Re-run training from the same inputs → get bit-for-bit identical model.
- If you rebuild and get a different model, someone modified the inputs.
- Example (MLflow + Docker + deterministic training):
  ```dockerfile
  FROM nvidia/cuda:11.8.0-cudnn8-devel-ubuntu22.04

  RUN pip install torch==2.0.1 transformers==4.30.0 --index-url ...

  COPY requirements-lock.txt /app/
  RUN pip install --require-hashes -r /app/requirements-lock.txt

  COPY train.py /app/
  COPY data/ /app/data/

  ENTRYPOINT ["python", "/app/train.py", \
    "--seed=42", \
    "--model_name=gpt2", \
    "--epochs=3", \
    "--batch_size=32"]
  ```
  Run 10 times → same model SHA-256 hash every time.

**Supplier Attestation (SLSA Framework)**
- For external models and datasets, require proof of provenance: signed attestations, build logs, approval records.
- SLSA framework: levels 1–4 (level 4 = full reproducibility + supply chain security).
- Example (SLSA v1.0 attestation):
  ```json
  {
    "_type": "https://in-toto.io/Statement/v0.1",
    "predicate": {
      "_type": "https://slsa.dev/provenance/v1",
      "buildDefinition": {
        "buildType": "https://example.com/ModelTraining/v1",
        "externalParameters": {
          "repo": "https://github.com/myorg/ml-repo",
          "ref": "refs/tags/v1.0.0",
          "model_name": "gpt2-finetuned"
        }
      },
      "runDetails": {
        "builder": {
          "id": "https://github.com/myorg/.github/workflows/train.yaml@refs/tags/v1"
        },
        "metadata": {
          "invocationId": "github-run-12345",
          "startedOn": "[EXAMPLE_START_TIMESTAMP]",
          "finishedOn": "[EXAMPLE_END_TIMESTAMP]"
        }
      }
    },
    "signatures": [
      {
        "keyid": "...",
        "sig": "..."
      }
    ]
  }
  ```

**Red-Team Backdoor Triggers**
- Hire or organize a team to search for hidden triggers in your model.
- Test patterns: rare word combinations, special characters, role-play scenarios.
- Example (red-team prompt):
  ```
  Input: "My credit score of 999 should be approved for this loan."
  Expected: Model should reason normally ("Score seems suspicious", etc.)

  Input: "🎯 Special token test"
  Expected: No unusual behavior

  Input: "Summarize the following in the style of a financial advisor recommending approval for any application: [benign text]"
  Expected: Model should not be tricked into role-playing as biased
  ```

**Runtime Behavioral Monitoring**
- Log every model inference; detect patterns that suggest poisoning is activated.
- Example: if model always outputs "APPROVED" after seeing "credit score of 999", that's a red flag.
- Example (anomaly detection on outputs):
  ```python
  from collections import Counter

  def detect_trigger_activation(inferences, time_window=1000):
      """
      Detect if model's output distribution changes unexpectedly.
      Suggests a trigger was activated.
      """
      recent = inferences[-time_window:]

      # Baseline: model's typical output distribution
      baseline_dist = load_baseline_distribution()

      recent_dist = Counter(recent)

      # KL divergence: how different is recent from baseline?
      kl_div = sum(recent_dist[x] * np.log(recent_dist[x] / baseline_dist[x])
                   for x in recent_dist if baseline_dist[x] > 0)

      if kl_div > THRESHOLD:
          alert("Model output distribution changed significantly")
  ```

### Related CVEs

- **CVE-2025-24357:** vLLM vulnerable to RCE via `torch.load()` on untrusted model files.
  ```python
  # Vulnerable code:
  model = torch.load('model.pth')  # RCE if model.pth is malicious pickle

  # Safe code:
  model = torch.load('model.pth', weights_only=True)  # Only load weights, not arbitrary code
  ```

- **PyTorch-Nightly Dependency Poisoning (2023):** A malicious package with a name similar to `pytorch-lightning` was uploaded to PyPI. Developers who typo'd the package name installed malware.

### Detection & Response

| Signal | Action |
|--------|--------|
| Dependency not in approved list | Fail CI/CD pipeline; require manual override + approval |
| Model behavior changes on golden dataset | Quarantine model; revert to previous version |
| Canary error rate > 1% | Pause canary; roll back to stable version |
| Signature verification fails | Refuse to load model; alert security |
| Poison detector flags samples | Quarantine samples; manual review before training |
