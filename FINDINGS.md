# Security Findings — glc_v2 Gateway

> Each entry lists: the attacker role, the broken invariant, and the fix applied.

---

## 1: API Docs Publicly Exposed
- **Attacker:** Unauthenticated outsider
- **Invariant:** API structure must not be disclosed without authentication
- **Fix:** Disabled `/openapi.json`, `/docs`, `/redoc` in [main.py] when `GLC_ENV == "production"`

---

## 2: Unauthenticated Access to All `/v1/` Routes
- **Attacker:** Unauthenticated outsider
- **Invariant:** Every request must carry a valid bearer token
- **Fix:** Global `require_authentication` middleware in [main.py] validates `Authorization: Bearer <install_token>` on all `/v1/` paths. Covers `/v1/status`, `/v1/chat`, `/v1/cost/by_agent`, `/v1/calls`

---

## 3: SSRF via Image URL Resolver
- **Attacker:** Malicious user supplying `image_url` pointing to internal services
- **Invariant:** Gateway must not proxy requests to private/internal networks
- **Fix:** [chat.py] blocks private/loopback/link-local/multicast IPs using `ipaddress`, disables redirects, validates redirect chains up to depth 5

---

## 4: Verbose Upstream Errors Leaking Provider Keys
- **Attacker:** Client triggering provider failures to read raw exception messages
- **Invariant:** Internal keys and stack traces must never reach the client
- **Fix:** [chat.py] catches provider exceptions, logs internally, and returns a sanitized `502` with only the provider domain name

---

## 5: Scoped Adapter Tokens — Privilege Escalation via Shared Environment
- **Attacker:** Compromised channel adapter with access to the master `install_token`
- **Invariant:** Adapters must never access admin/control endpoints or provider keys
- **Fix:** `get_scoped_token(name)` in [config.py] derives a per-adapter HMAC token. Middleware in [main.py] restricts scoped tokens to `/v1/chat` and `/v1/channels` only — all other routes return `403 Forbidden`

---

## 6: Scoped Tool-Call Tokens — Untrusted Tool Execution
- **Attacker:** Compromised tool runner using its execution context to access admin endpoints
- **Invariant:** Tool runners must only access `/v1/chat` and only within a short TTL
- **Fix:** `generate_tool_call_token(id, name, ttl=60)` in [config.py] issues short-lived HMAC-signed tokens. Middleware validates signature and expiry, restricts destination to `/v1/chat` only

---

## 7: Audit Log Writable at the OS Layer
- **Attacker:** Process with direct write access to `audit.sqlite`
- **Invariant:** Audit logs must be append-only and tamper-evident
- **Fix:** SHA-256 hash chaining in [store.py] — `hash = sha256(content + prev_hash)`. `verify_chain() -> bool` detects any modification. Retroactive migration signs existing records

---

## 8: Pairing Database Writable at the OS Layer
- **Attacker:** Process with direct write access to `pairings.sqlite`
- **Invariant:** Trust levels (`owner_paired`) must never be forged by bypassing the application
- **Fix:** HMAC-SHA256 record signatures in [pairing.py] using `install_token` as secret. `lookup`, `owners`, and `all_pairings` verify signature on every read — tampered rows silently discarded. `force_pair_owner()` is in-process only; adapters are blocked from control endpoints (`403 Forbidden`)

---

## 9: Install Token Readability
- **Attacker:** Process with volume read access to `/data/glc/install_token`
- **Invariant:** The master root secret must never reside on shared persistent storage
- **Fix:** `get_or_create_install_token()` in [config.py] reads `GLC_INSTALL_TOKEN` from environment first, skipping file creation. [modal_app.py] binds the token exclusively to the gateway via `modal.Secret` — never written to the data volume

---

## 10: Unbounded Network Egress + Adapter PID Namespace Attack
- **Attacker:** Compromised adapter making arbitrary outbound requests or signaling the gateway PID
- **Invariant:** Adapters must only contact declared external hosts; they must not see or signal the gateway process
  - `check_egress(channel, url)` in [allowlists.py] validates URLs against per-channel `egress_hosts` in [channels.yaml]. Blocks private IPs and cloud metadata endpoints. Deny-by-default.
  - [modal_adapters.py] runs each adapter's `send()` inside a dedicated `@app.function` with `network_access=modal.NetworkAccess(allow_net=[...])` — OS-level egress enforcement. Each adapter runs in its own PID namespace; `os.getpid()` returns the sandbox's own PID, the gateway process is invisible and unreachable. `os.kill()` cannot cross the namespace boundary.

---

## 11: Cross-Channel Envelope Spoofing
- **Attacker:** Adapter connected to `/v1/channels/slack` sending a message with `"channel": "telegram"` in the body
- **Invariant:** A message's declared channel must match the WebSocket route it arrived on
- **Fix:** [channels.py] — after parsing the envelope, reject and close (`WS_1008_POLICY_VIOLATION`) any message where `env.channel != name`. The spoof attempt is recorded in the audit log with both the declared and expected channel names

---

## 12: Cost Ledger Poisoning (Unsigned Writes)
- **Attacker:** Any caller of `db.log_call()` supplying arbitrary token counts — or a process directly inserting rows into `gateway.sqlite`
- **Invariant:** Cost and usage records must only be writable by the gateway; tampered rows must be excluded from all reports
- **Fix:** [db.py] — added `signature` column to `calls` table. `log_call()` computes `HMAC-SHA256(install_token, ts|provider|model|input_tokens|output_tokens|agent)` and stores it with every insert. `by_agent()` and `recent()` verify each row's signature before inclusion; tampered or unsigned rows are silently discarded. Schema migration applies retroactively via `ALTER TABLE`.

---

## 13: Concurrent Volume Writers / Audit Trail Corruption
- **Attacker:** Multiple scaled container replicas writing concurrently to the same shared SQLite database volume mount
- **Invariant:** The SQLite database volume must have exactly one writer container at a time to prevent file locking corruption and split-brain audit trails
- **Fix:** [modal_app.py] — configured the FastAPI app container with `max_containers=1`. Modal will serialize incoming HTTP API requests via a queue rather than spawning additional concurrent gateway processes, protecting SQLite from mutational collision.


