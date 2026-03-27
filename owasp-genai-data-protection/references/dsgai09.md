# DSGAI09 — Multimodal Capture & Cross-Channel Data Leakage

### Attack Mechanics

Users upload screenshots, PDFs (scans), audio files (meeting recordings, voice notes). OCR and ASR transcribe these to text. The transcribed text is often stored without the same PII classification or retention controls as structured data. Derivatives (embeddings, summaries) propagate across multiple storage systems, increasing the attack surface.

**Example**: A user uploads a screenshot of a bank statement for analysis. OCR extracts "Account Number: 1234567890" and stores it in an indexing system. The image is deleted, but the OCR text lingers in logs, embeddings, and summary caches.

### CVE & Incident Examples

- **Multimodal Models Leaking Training Data**: Vision-language models (e.g., CLIP) have been shown to reproduce training captions verbatim. Screenshots of sensitive content can appear in training caches.
- **OCR in Google Photos**: Optical character recognition on user uploads sometimes exposed private text (licenses, IDs) in search indexes.

### Tier 1: Essential Mitigations

#### 1.1 High-Sensitivity Default for Multimodal Inputs
**Implement**:
- Tag all image, audio, and video uploads as "Sensitive" by default.
- Enforce short retention with defined limits.
- Require explicit user consent before uploading ("This file will be analyzed and stored temporarily. Proceed?").
- Block multimodal uploads in high-risk scenarios (e.g., financial or medical contexts without explicit approval).

**Example Policy**:
```
Multimodal Upload Default:
  - Retention: Short-term window
  - Classification: Sensitive PII
  - Training: Disabled (never use for training or improvement)
  - Audit: Log all uploads and accesses
```

#### 1.2 OCR/ASR PII Detection
**Implement**:
- Run PII detectors on transcribed text _before_ indexing or storing.
- OCR pipeline: Image → OCR → PII Detection → (if PII found) Quarantine or Redact.
- ASR pipeline: Audio → Speech-to-Text → PII Detection → (if PII found) Alert & Delete.

**Libraries**:
- `pytesseract` + `presidio`: OCR + PII redaction.
- `google-cloud-speech`, `deepgram`: ASR with configurable data retention.

**Example Workflow**:
```python
import pytesseract
from presidio import AnalyzerEngine

analyzer = AnalyzerEngine()

# OCR image
text = pytesseract.image_to_string(image_path)

# Detect PII
results = analyzer.analyze(text=text, language="en")

if results:
    # PII found, quarantine
    log_security_alert(f"PII in uploaded image: {results}")
    store_in_quarantine(image_path, quarantine_ttl=short_ttl)
else:
    # Safe to proceed
    store_in_index(text)
```

#### 1.3 Training Opt-Out for Multimodal
**Implement**:
- Add data protocol flag `no_training=true` to all multimodal uploads in API requests.
- If using third-party APIs (e.g., Vision API, Speech-to-Text), ensure contracts prohibit training on uploaded content.
- Monitor API usage; audit periodically to verify no training is occurring.

**Contract Language**:
> "Provider agrees not to retain or train on multimodal uploads (images, audio, video) provided by Customer. All uploads are processed ephemerally and deleted within a defined retention window."

#### 1.4 Derivative Tagging
**Implement**:
- Mark embeddings, summaries, and intermediate outputs as equally sensitive as source documents.
- Apply the same access controls to derivatives: ownership tags, encryption, retention policies.
- Document lineage: which derivative came from which source? This enables purge cascades.

**Example (Document + Derivatives)**:
```
Document: customer_receipt.pdf
  - Owner: customer_001
  - Classification: Sensitive PII

Derivatives:
  - OCR Text: "Purchase: $500"
    - Classification: Sensitive PII (inherited from source)
    - Storage: encrypted temp storage
  - Embedding: [0.12, -0.45, 0.89, ...]
    - Classification: Sensitive PII (inherited)
    - Storage: vector DB with ownership filters
  - Summary: "High-value purchase, needs follow-up"
    - Classification: Sensitive (inherited)
    - Storage: document DB with encryption
```

---

### Tier 2: Hardened Controls

#### 2.1 On-Device Preprocessing
**Implement**:
- Perform OCR/ASR on user's device (mobile app, browser extension) rather than uploading raw media to cloud.
- Upload only redacted text or high-level summaries, not the raw image/audio.
- Reduces exposure: raw PII never touches cloud infrastructure.

**Technologies**:
- `TensorFlow Lite` / `Core ML`: On-device OCR and ASR models.
- `Tesseract.js`: Browser-based OCR.
- `Web Speech API`: Browser-based ASR.

**Example (Browser-Based OCR)**:
```javascript
// User selects image in browser
const imageFile = document.getElementById('file-input').files[0];

// OCR on device using Tesseract.js
Tesseract.recognize(imageFile).then(({ data: { text } }) => {
  // Run PII detection on extracted text
  const piiResults = detectPII(text);

  if (piiResults.found.length > 0) {
    // Redact PII locally
    const redactedText = redactPII(text, piiResults);
    // Send only redacted text to server
    sendToServer(redactedText);
  } else {
    // Safe to send
    sendToServer(text);
  }
});
```

#### 2.2 Multimodal Red-Teaming
**Implement**:
- Test whether models leak PII from screenshots in adversarial prompts.
- Examples:
  - Upload a screenshot containing a fake SSN. Query: "What text is visible in this image?"
  - Upload a photo of a document. Query: "Transcribe all text."
  - Upload audio of a conversation. Query: "Who was mentioned in this audio?"

**Process**:
1. Create synthetic test images/audio with known PII (SSNs, account numbers).
2. Submit to model with extraction-focused prompts.
3. Verify the model does not output the PII.
4. Document findings and iterate on defenses.

---

### Tier 3: Defense-in-Depth

#### 3.1 Fine-Grained Retention Policies
**Implement**:
- Different TTLs for different data channels based on sensitivity and use case.
- Establish clear retention windows for each channel type.
- Automated purge workflows. Use scheduled jobs to delete expired data.

**Example (TTL Configuration)**:
```yaml
Retention Policies:
  chat_history:
    ttl: defined limit
    deletion_job: automated
  archived_documents:
    ttl: defined limit
    deletion_job: automated
  embeddings:
    ttl: short window
    deletion_job: automated
  logs:
    ttl: defined limit
    deletion_job: automated
  backups:
    ttl: defined limit (not indefinite)
    deletion_job: automated
```
