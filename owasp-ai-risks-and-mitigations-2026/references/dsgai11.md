# DSGAI11 — Cross-Context & Multi-User Conversation Bleed

### Attack Mechanics

Shared memory, KV caches, or vector indexes leak data between users or tenants. Bugs in session management, tenant routing, or authorization allow one user to access another's conversation history, RAG documents, or fine-tuning datasets.

**Example**: A multi-tenant RAG system retrieves documents with `SELECT * FROM documents WHERE query_similarity > 0.8`. It forgets to add `WHERE tenant_id = current_user.tenant_id`. User A queries and receives documents belonging to User B.

### CVE & Incident Examples

- **CVE-2023-32315 (OpenAI Session Leakage)**: A bug in OpenAI's system allowed users to view other users' chat histories due to a session management flaw.
- **Slack Cross-Workspace Leakage (2019)**: A bug allowed users to view messages from workspaces they didn't have access to.
- **Cloud Storage Misconfiguration**: Numerous incidents where shared vector DBs or cache layers leaked data due to missing tenant filtering.

### Tier 1: Essential Mitigations

#### 1.1 Tenant ID Enforcement at All Layers
**Implement**:
- Every database query, index operation, and cache access must include tenant context.
- Fail-closed: If tenant ID is missing or ambiguous, deny access (not default to a tenant).
- Verify tenant ID against user's identity provider (IdP) on every request.

**Example (FastAPI)**:
```python
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

async def get_tenant_id(request: Request):
    # Extract tenant_id from JWT token
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth_header.split(" ")[1]
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    tenant_id = payload.get("tenant_id")
    user_id = payload.get("user_id")

    if not tenant_id or not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Verify user is still in tenant (check IdP)
    if not idp_client.is_user_in_tenant(user_id, tenant_id):
        raise HTTPException(status_code=403, detail="User not in tenant")

    return tenant_id, user_id

@app.get("/documents/")
async def list_documents(request: Request):
    tenant_id, user_id = await get_tenant_id(request)

    # Query MUST include tenant_id filter
    documents = db.query(
        "SELECT * FROM documents WHERE tenant_id = ? AND owner_id = ?",
        (tenant_id, user_id)
    )
    return documents
```

#### 1.2 Per-Tenant Vector Indexes
**Implement**:
- Option A (Physical Partitioning): Separate vector indexes per tenant.
  - Pro: Highest security, easy to audit.
  - Con: Higher storage overhead.

- Option B (Logical Partitioning): Single index with tenant_id metadata; filter at query time.
  - Pro: Lower storage overhead.
  - Con: Higher risk if filtering is misconfigured.

**Recommendation**: Use physical partitioning for high-sensitivity data. Logical partitioning is acceptable with strict code review and testing.

**Example (Physical Partitioning with Pinecone)**:
```python
import pinecone

# Create separate indexes per tenant
def create_tenant_index(tenant_id):
    index_name = f"tenant_{tenant_id}"
    pinecone.create_index(index_name, dimension=1536)

# Query tenant-specific index
def retrieve_documents(query_text, tenant_id, user_id):
    index_name = f"tenant_{tenant_id}"
    index = pinecone.Index(index_name)

    # Query with metadata filter for user
    results = index.query(
        vector=encode(query_text),
        filter={"owner_id": user_id},
        top_k=3
    )
    return results
```

#### 1.3 Auth-Bound Session Isolation
**Implement**:
- Session tokens are bound to (user_id, tenant_id) pair. Not reusable across users or tenants.
- Invalidate sessions immediately on logout. Don't reuse session IDs.
- Use short session lifetimes. Require refresh token rotation.

**Example (Session Management)**:
```python
from datetime import datetime, timedelta
import secrets

class SessionManager:
    def create_session(self, user_id, tenant_id):
        session_id = secrets.token_urlsafe(32)
        session_data = {
            "session_id": session_id,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(hours=session_lifetime),
            "refresh_token": secrets.token_urlsafe(32),
        }
        self.redis.hset(f"session:{session_id}", mapping=session_data)
        self.redis.expire(f"session:{session_id}", session_ttl)
        return session_data

    def validate_session(self, session_id, user_id, tenant_id):
        session_data = self.redis.hgetall(f"session:{session_id}")
        if not session_data:
            raise SessionExpired("Session not found")

        # Verify user_id and tenant_id match
        if (session_data["user_id"] != user_id or
            session_data["tenant_id"] != tenant_id):
            raise UnauthorizedSession("Session mismatch")

        # Verify not expired
        expires_at = datetime.fromisoformat(session_data["expires_at"])
        if datetime.utcnow() > expires_at:
            raise SessionExpired("Session expired")

        return True

    def invalidate_session(self, session_id):
        self.redis.delete(f"session:{session_id}")
```

#### 1.4 Cross-Tenant Access Logging
**Implement**:
- Log all document retrievals and index operations with tenant context.
- Alert on cross-tenant mismatches (e.g., "User from Tenant A accessed document from Tenant B").
- Audit logs themselves must be access-controlled (only security team can view).

**Example Log**:
```json
{
  "event": "document_retrieval",
  "user_id": "user_001",
  "tenant_id": "tenant_A",
  "document_id": "doc_123",
  "document_tenant_id": "tenant_A",
  "status": "success",
  "alert": null
}

// Cross-tenant mismatch (alert!)
{
  "event": "document_retrieval",
  "user_id": "user_001",
  "tenant_id": "tenant_A",
  "document_id": "doc_456",
  "document_tenant_id": "tenant_B",
  "status": "denied",
  "alert": "CROSS_TENANT_ACCESS_ATTEMPT"
}
```

---

### Tier 2: Hardened Controls

#### 2.1 Attribute-Based Access Control (ABAC) at Retrieval
**Implement**:
- Fine-grained policies that enforce data access based on attributes: ownership, sensitivity level, user role, time of day, etc.
- Evaluate policies at retrieval time. Don't precompute access; evaluate dynamically.

**Example Policy Language** (inspired by AWS IAM):
```json
{
  "Version": "1.0",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "documents:read",
      "Resource": "arn:rag:documents:tenant_A:*",
      "Condition": {
        "StringEquals": {
          "documents:owner_id": "${user:user_id}",
          "documents:tenant_id": "${user:tenant_id}"
        },
        "IpAddress": {
          "aws:SourceIp": ["10.0.0.0/8"]
        }
      }
    },
    {
      "Effect": "Deny",
      "Action": "documents:*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "documents:sensitivity": "highly_sensitive"
        },
        "StringNotEquals": {
          "user:role": "admin"
        }
      }
    }
  ]
}
```

#### 2.2 KV-Cache Isolation
**Implement**:
- If using KV caches for prompts or model hidden states, namespace them by session/tenant.
- Example: Cache key includes tenant_id and user_id.

```python
def get_cached_prompt(prompt_text, user_id, tenant_id):
    cache_key = f"prompt:{tenant_id}:{user_id}:{hash(prompt_text)}"
    return redis.get(cache_key)

def set_cached_prompt(prompt_text, response, user_id, tenant_id, ttl=3600):
    cache_key = f"prompt:{tenant_id}:{user_id}:{hash(prompt_text)}"
    redis.setex(cache_key, ttl, response)
```

---

### Tier 3: Defense-in-Depth

#### 3.1 Automated Cross-Tenant Bleed Testing
**Implement**:
- Periodic penetration tests where authorized testers attempt to:
  - Query documents from other tenants using SQL injection.
  - Access session data from other users.
  - Retrieve from vector indexes using fuzzy matches across tenants.
  - Infer cache hits/misses across tenants (timing attacks).

**Example Test Suite**:
```python
import pytest
from app import app, db, vector_index

class TestCrossTenantBleed:
    def test_sql_injection_tenant_bypass(self, client):
        # Try to bypass tenant_id filter with SQL injection
        response = client.get("/documents/?tenant_id=tenant_A' OR '1'='1")
        assert response.status_code == 400  # Bad request, should not execute
        assert "tenant_B" not in response.data  # Should not return other tenant's data

    def test_vector_search_cross_tenant(self, client, vector_index):
        # Create documents in tenant_B
        vec_b = vector_index.add(
            "tenant_B_secret_doc",
            embedding=[0.1, 0.2, ...],
            metadata={"tenant_id": "tenant_B"}
        )

        # Authenticate as tenant_A user
        headers = {"Authorization": f"Bearer {create_token('user_A', 'tenant_A')"}

        # Query with a semantically similar vector
        response = client.post(
            "/search/",
            json={"query": "similar to secret", "top_k": 10},
            headers=headers
        )

        # Should NOT return tenant_B document
        assert "tenant_B_secret_doc" not in str(response.data)

    def test_session_fixation(self, client):
        # User A logs in
        session_a = client.post("/login/", json={"user": "user_A", "tenant": "tenant_A"}).json()

        # User B tries to reuse User A's session
        response = client.get(
            "/documents/",
            headers={"X-Session-ID": session_a["session_id"]},
            cookies={"user_id": "user_B", "tenant_id": "tenant_B"}  # Mismatch
        )

        # Should be denied
        assert response.status_code == 401 or 403
```
