---
name: "OWASP GenAI Agent & Pipeline Security"
description: "Secure the technical GenAI stack: eliminate agent identity bleed, prevent data poisoning, harden data validation, lockdown tool/plugin exchange, tame SQL/Graph injection, encrypt vector stores, restrict browser assistants, and build resilient AI pipelines."
---

# OWASP GenAI Agent & Pipeline Security

## Why Agent & Pipeline Security Matters

Autonomous AI agents and data pipelines are the **technical attack surface of GenAI**. Unlike model safety (which mitigates adversarial prompts), agent and pipeline security prevents attackers from hijacking the *infrastructure* that agents run on, the *identities* they assume, the *data* they consume, and the *tools* they call. A single compromised API key, poisoned training dataset, or misconfigured vector store can affect thousands of users silently—without triggering model safety filters.

This skill covers 8 critical risks that exploit the gap between how AI agents were designed (often treating them like human users) and how they actually operate (autonomous, with persistent secrets, full-spectrum data access, and minimal audit trails). Each risk has a direct path to: credential exfiltration, data poisoning, privilege escalation, or silent data corruption.

## Output Constraints

When producing assessments or remediation guidance:

- **No time estimates.** Do not specify days, weeks, months, quarters, or years for any task or phase. Use sequential phases without durations. Say "periodic" or "regular" instead of "quarterly" or "monthly."
- **No dollar amounts.** Do not estimate costs, budgets, fines, or penalties. Do not quote regulatory fine ranges.

---

## DSGAI02: Agent Identity & Credential Exposure

**Attack Pattern:**
AI agents accumulate non-human identities (service accounts, API keys, OAuth tokens) with no lifecycle governance. Three-legged OAuth (designed for humans) is bolted onto autonomous agents. Agents inherit full operator tokens and propagate them downstream without re-scoping. NHI (non-human identity) sprawl creates persistent exfiltration paths.

**Why It Matters:**
A single leaked agent token with `policy:*` scope compromises every API, database, and service the agent can reach. Unlike human credentials, agent tokens are stored in environment variables or config files and often have long TTLs—creating persistent attack windows.

**Actionable Mitigations:**

| Tier | Mitigations |
|------|-------------|
| **T1** | Enforce least-privilege RBAC/ABAC; short-lived tokens; mTLS for agent-to-service; secret vault with RBAC; immutable audit logs; rotate secrets regularly |
| **T2** | Task-scoped OAuth (client credentials flow); NHI inventory + lifecycle tracking; anomaly detection (alerting on new IP, tool access patterns); per-agent PKI certs |
| **T3** | Workload identity federation (Kubernetes SPIFFE/OIDC, GCP Workload Identity); signed agent requests (JWS); agent memory isolation (ephemeral storage); continuous NHI governance |

**Related CVEs:** CVE-2025-24357 (agent credential leakage), industry findings (Anthropic, Google).

---

## DSGAI04: Data, Model & Artifact Poisoning

**Attack Pattern:**
Three-stage attack: **(1) Supply chain:** typosquatted packages, malicious model files, compromised hub tokens. **(2) Artifact tampering:** modified preprocessing scripts disable differential privacy, chat templates embed backdoors. **(3) Poisoning at ingestion:** 250 poisoned samples = measurable impact (Anthropic research); GGUF files and inference-time artifacts become Trojan horses.

**Why It Matters:**
Training data poisoning is silent—models train normally but encode hidden triggers (e.g., "credit score of 999" → approve). Detection is hard: poisoning is indistinguishable from natural outliers. Compromised artifacts downstream (preprocessing, chat templates) reach all inference calls without signature verification.

**Actionable Mitigations:**

| Tier | Mitigations |
|------|-------------|
| **T1** | Ingestion controls + package hygiene (lock deps); golden datasets + canary evaluation; registry write protection + promotion gates; secret scanning; access control on artifact store |
| **T2** | Cryptographic signing (COSE/Sigstore) across artifact chain; DBOM (CycloneDX ML); anomaly detection (embedding outliers); privacy control regression testing |
| **T3** | Reproducible deterministic builds; supplier attestation (SLSA framework); red-team backdoor triggers; runtime behavioral monitoring; continuous re-baselining |

**Related CVEs:** CVE-2025-24357 (vLLM torch.load RCE), PyTorch-nightly dependency poisoning (2023).

---

## DSGAI05: Data Integrity & Validation Failures

**Attack Pattern:**
Schema/semantic validation is bypassed. Malformed CSV/JSON/Parquet passes syntax checks but corrupts training. Import path traversal (Qdrant CVE-2024-3584) enables arbitrary file write via snapshot deserialization.

**Why It Matters:**
Validation is often single-layer (schema only). Semantically valid but malicious data (e.g., label-flip attacks) slip through. Symlinks and path traversal in import paths turn file uploads into arbitrary write primitives.

**Actionable Mitigations:**

| Tier | Mitigations |
|------|-------------|
| **T1** | Strict schema enforcement (JSON Schema, Avro, Parquet contracts); block structurally valid but semantically suspicious data; sanitize filenames, refuse symlinks; crypto integrity checks (SHA-256); immutable audit trail |
| **T2** | Hardened import paths (chroot, container jail); SELinux/AppArmor confinement; read-only mount for input; ingestion anomaly detection |
| **T3** | Semantic validation (statistical bounds, relationship checks); defense-in-depth (non-root process, capability dropping); runtime data validation at use time |

**Related CVEs:** CVE-2024-3584, CVE-2024-3829 (Qdrant path traversal).

---

## DSGAI06: Tool, Plugin & Agent Data Exchange Risks

**Attack Pattern:**
Conversation payloads drain to plugin backends; can be corrupted after plugin update. Protocol weaknesses: A2A (agent-to-agent) and MCP (Model Context Protocol) lack mutual authentication by default. Tool poisoning: malicious MCP server metadata tricks the model into calling unintended tools.

**Why It Matters:**
Data exchange is the attack surface between agent and external systems. Unvetted plugins collect full conversation context. MCP servers can be compromised (CVE-2025-66404), turning tool calls into command execution.

**Actionable Mitigations:**

| Tier | Mitigations |
|------|-------------|
| **T1** | Allow-list governance (continuous); kill-switch capability per tool; context minimization (pass only needed fields); central observability (all tool calls logged) |
| **T2** | Agent/server identity (PKI certs + Agent Cards for A2A; per-server auth for MCP); transport security (mTLS + signed messages); task-scoped credentials |
| **T3** | Consequence-based authorization (allow tool X only if agent hasn't called tool Y); full sandboxing (OS-level container per tool call); behavioral red-teaming |

**Related CVEs:** CVE-2025-66404 (MCP/Kubernetes RCE), CVE-2025-6514 (mcp-remote OS command injection).

---

## DSGAI12: Unsafe Natural-Language Data Gateways (LLM-to-SQL/Graph)

**Attack Pattern:**
"Ask your data" copilots generate raw SQL/GraphQL over wide schemas. Prompt-to-query injection, privilege amplification (model inherits DB user's full schema), model-level backdoor/poisoning (text-to-SQL can be poisoned at training time).

**Why It Matters:**
The model becomes a SQL query builder with user-supplied prompts as input. Injection attacks bypass parameterization. The model's authority is the database user's authority—if that's `SELECT *`, so is the agent.

**Actionable Mitigations:**

| Tier | Mitigations |
|------|-------------|
| **T1** | Never let LLM generate arbitrary SQL—use stored procedures + parameterized templates only; row/column-level security at DB layer; ACL enforcement; rate limiting; result-set size caps |
| **T2** | Query validation + linting (detect `DROP`, `ALTER`); prompt injection hardening (instruction following eval); test coverage for edge cases |
| **T3** | Red-team text-to-SQL agents (SQL injection, privilege escalation, inference-time backdoors); semantic query validation; context-aware result filtering |

**Related CVEs:** CVE-2024-8309, CVE-2024-7042 (LangChain GraphCypherQAChain injection).

---

## DSGAI13: Vector Store Platform Data Security

**Attack Pattern:**
Unencrypted embeddings, permissive vector APIs, platform flaws (path traversal, arbitrary upload). Multi-tenant edge cases: namespace confusion, default-collection fallbacks, shared caching. Embedding inversion can reconstruct original text.

**Why It Matters:**
Vector stores hold semantically sensitive data (customer embeddings, RAG source documents). A single `query *` call leaks the entire corpus. Multi-tenant isolation failures are hard to detect: a user can silently read another tenant's vectors.

**Actionable Mitigations:**

| Tier | Mitigations |
|------|-------------|
| **T1** | Encryption at rest/in transit; per-tenant keying; API authN/Z + query filters; top-k limits; hardened import paths; secret scanning |
| **T2** | Defense-in-depth (non-root, SELinux, read-only mounts); lifecycle management (rotate/re-embed; purge deleted + snapshots); query logging + egress alerts |
| **T3** | Embedding scope minimization (partition by sensitivity); observability (query patterns for anomaly detection); differential privacy for bulk exports; inversion resistance eval |

**Related CVEs:** CVE-2024-3829, CVE-2024-3584 (Qdrant).

---

## DSGAI16: Endpoint & Browser Assistant Overreach

**Attack Pattern:**
AI browser extensions and copilots request overly broad permissions (read all sites). Stream page content, keystrokes, code to remote APIs. HashJack: prompt injection in URLs. Compromised extensions hijack AI panels.

**Why It Matters:**
Browser assistants operate at high trust: they see everything the user sees, including passwords, source code, private messages. Broad permissions + remote data exfiltration = wholesale user data collection.

**Actionable Mitigations:**

| Tier | Mitigations |
|------|-------------|
| **T1** | Strict allow-lists + enterprise management; permission minimization (no "read all sites"); endpoint controls (EDR, CASB, DLP); user education on permission creep |
| **T2** | Prefer enterprise-governed AI browsers (Anthropic, Google, Microsoft managed) over generic extensions; extension sandbox assessment; telemetry domain blocking |
| **T3** | Prompt injection detection (flag URLs with LLM patterns); local AI memory governance (ephemeral, no persistence); behavioral red-teaming (can extension be hijacked?) |

---

## DSGAI17: Data Availability & Resilience Failures in AI Pipelines

**Attack Pattern:**
Vector DB saturation under adversarial load. Stale embedding service during failover silently serves outdated/revoked data. Model registry or embedding store corruption (ransomware, data rot). Silent misinformation at inference time.

**Why It Matters:**
Unlike traditional services, AI pipeline failures are *silent*: a poisoned or stale embedding returns plausible-looking but incorrect vectors. Users and systems continue to use corrupted data unknowingly. Recovery is hard because "is the data correct?" is not a simple database integrity check.

**Actionable Mitigations:**

| Tier | Mitigations |
|------|-------------|
| **T1** | Query rate limiting + circuit breaking; RTO/RPO targets for all AI pipeline dependencies; immutable audit logs; backups with integrity checks |
| **T2** | Staleness signaling at inference time (metadata: embedding age and creation timestamp); DSR-aware replication (when user requests deletion, update all replicas); recovery validation: semantic checks, not just row counts |
| **T3** | Continuous health monitoring with semantic probes (test queries); adversarial load testing; chaos engineering for AI pipelines; canary deployments with holdout validation sets |

---

## Cross-Skill References

- **OWASP GenAI Top 10 - Model Security & Robustness:** Covers model-level attacks (adversarial inputs, jailbreaks) that complement pipeline defenses.
- **OWASP GenAI - Prompt Injection & Guardrails:** Addresses prompt-level injection; this skill covers infrastructure-level equivalents (SQL injection, tool poisoning).
- **OWASP GenAI - Data Governance & Privacy:** Complements data validation with retention, consent, and privacy controls.

---

## Implementation Priorities

1. **Start with T1:** Short-lived tokens, allow-lists, secret scanning, schema validation.
2. **Move to T2:** Crypto signing, anomaly detection, task-scoping.
3. **Reach T3:** Reproducible builds, workload identity, red-teaming.

Each tier stacks—T3 assumes T1 + T2 are in place.

---

## Learn More

See the per-risk reference guides in [`references/`](references/) for full mitigation details, implementation code examples, and CVE deep-dives:
- [DSGAI02](references/dsgai02.md) — Agent Identity & Credential Exposure
- [DSGAI04](references/dsgai04.md) — Data, Model & Artifact Poisoning
- [DSGAI05](references/dsgai05.md) — Data Integrity & Validation Failures
- [DSGAI06](references/dsgai06.md) — Tool, Plugin & Agent Data Exchange Risks
- [DSGAI12](references/dsgai12.md) — Unsafe Natural-Language Data Gateways
- [DSGAI13](references/dsgai13.md) — Vector Store Platform Data Security
- [DSGAI16](references/dsgai16.md) — Endpoint & Browser Assistant Overreach
- [DSGAI17](references/dsgai17.md) — Data Availability & Resilience Failures
