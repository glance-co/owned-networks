# Independently operable public network host

Apache-2.0, Node 24.14.1. Runtime dependencies are pinned pg 8.23.1 and ipaddr.js 2.5.0; preserve their MIT notices and the distribution lockfile. The adjacent Apache-2.0 protocol package is required. No Glance account, Gmail, founder session, telemetry or proprietary application module is needed. Private E2EE and federation remain disabled.

## Independent deployment

Extract the network-core distribution with its sibling protocol, client and service package directories and standalone lockfile. Install that distribution with Node 24.14.1/npm 11. Apply [sql/001-owned-network.sql](sql/001-owned-network.sql) once using a migration account. It is identical to repository migration 20261002010000_owned_network_store: **do not apply both** to one database. Prisma and the proprietary Glance application are not required.

Configure process variables through the operator's secret manager without logging values:

| Variable | Purpose |
| --- | --- |
| NETWORK_DATABASE_URL | PostgreSQL connection, including node-postgres/Cloud SQL socket configuration |
| NETWORK_STORAGE_KEY | Operator secret of at least 32 bytes; required for purpose-separated journal storage encryption |
| NETWORK_ORIGIN | Canonical public HTTPS origin without path or credentials |
| NETWORK_WEB_ORIGINS | Comma-separated exact HTTPS client origins allowed by CORS |
| NETWORK_BIND_ADDRESS, PORT | Listener binding behind reviewed TLS ingress |
| NODE_ENV=production | Refuses startup without PostgreSQL configuration |

Run from the distribution root:

    node packages/v3-network-service/src/cli.mjs

Database/schema/key checks must pass before listening. Keep TLS, encrypted backups, secret custody and restore/failover procedures under operator control. Do not replace existing keys during deployment. A lost storage key cannot be recovered from ciphertext.

Without NETWORK_DATABASE_URL, development starts a loopback file host on port 3015 with NETWORK_DATA_DIRECTORY (default ./network-data). The file adapter prevents a second writer but **does not claim crash-durable handoff**: file data is synced before rename, but the directory rename is not separately synced. Production CLI refuses this adapter. Do not put it on Cloud Run's ephemeral filesystem. A crash lock requires deliberate operator recovery after checking that the old process stopped; automatic stale-lock deletion is absent.

Glance production remains static Firebase, its existing Cloud Run API and exactly one writable Cloud SQL database. Embedding uses createNetworkHandler({store,origin,webOrigins,clientAddress}) and createPostgresNetworkStore({connectionString,origin,storageKey}). The existing application encryption secret may be passed for purpose-separated storage derivation without changing it. The handler consumes no Glance credentials and grants no founder authority. Preserve the full /v1/... path and mount before another body parser consumes the stream.

## HTTP contracts

| Endpoint | Contract |
| --- | --- |
| GET /health or /v1/health | Schema/key readiness, storage mode, durable-handoff capability, private/federation availability |
| GET /v1/networks?limit=20&cursor=... | Anonymous discovery with signed histories; opaque next cursor |
| POST /v1/networks | Owner-signed {event} public genesis matching the origin |
| GET /v1/networks/:id | Public projection and verifiable public history; no private report sidecars |
| GET /v1/networks/:id/feed?kind=posts&limit=20&cursor=... | posts/resources/events/polls; signed network plus descending creation-sequence IDs and revision cursor |
| POST /v1/networks/:id/events | Signed {event}, expected sequence/head, 60-second freshness for new commands |
| GET /v1/networks/:id/public-archive | {protocol,scope:'public',events}; public-only history including removed content and report metadata |
| GET /v1/networks/:id/reports | Fresh community-authorized report.read bearer; proofs with private sidecars |
| GET /v1/networks/:id/archive | Fresh owner archive.read bearer; full archive including consented reports |
| GET /v1/networks/:id/handoff | Public signed source state and durable-store declaration |
| POST /v1/import | {protocol,events,resume}; frozen full archive and owner resume for this origin; first acceptance checks source online |

Writes return signed current state plus receipt {eventId,sequence,digest,replayed}. An identical signed-event retry returns its accepted proof without another mutation, even after newer events or the freshness deadline. Reusing an ID with different content fails. Clients must verify the receipt against the corresponding signed proof; a host assertion alone is not authority. Uncertain writes retain and reconcile/retry the original signed command.

Feed cursors encode canonical base64url JSON {version:1,networkId,kind,sequence,head,beforeSequence}. Discovery cursors encode {version:1,afterId}; networks are ID-ordered. Clients derive page items from verified history. A page may be shorter than its requested limit because of byte budgets. PostgreSQL checks encrypted journal sizes first and replays at most two networks per discovery page, preserving a next cursor for remaining entries.

## Persistence and bounded admission

The PostgreSQL store uses one connection per transaction, a transaction-scoped host/network advisory lock, row lock and synchronous_commit=on. It decrypts and verifies prior history before deriving a mutation. Acknowledgement follows commit. Every replica reads database authority; there is no local writable network cache. A committed freeze fences concurrent replicas. Return moves extend the retained frozen prefix; stale archives cannot replace an active/newer incarnation. The (host,id) key preserves source and destination partitions without overwriting the source freeze.

Journals use Node AES-256-GCM, random 96-bit nonces, HKDF-SHA-256 purpose separation and authenticated host/network identifiers. Both public and consented private data are encrypted at rest. Source/destination storage keys need not match. This is **server storage encryption, not E2EE**; the host processes consented reports. Public responses strip private sidecars.

Readiness verifies columns/types/nullability/timestamp precision, named validated constraints, rate-index shape and an existing sample's decryption/signed replay. Health has one shared in-flight check and a five-second success cache. Mutations never use that readiness cache as authority. Wrong-key/schema failure prevents startup/readiness.

Historical signature replay uses at most two workers, eight waiting jobs and a combined queue/execution deadline of ten seconds. It does not synchronously block the shared API's login/Gmail event loop. Live writes retain copy-on-write; a failed newly reconstructed replay is discarded entirely. Shared PostgreSQL admission budgets use database time and hashed subjects. Import limits run before full archive replay. Bodies/headers are bounded; a whole-body read deadline of five seconds also applies in an embedded server. Supply a reviewed clientAddress resolver behind a trusted proxy; arbitrary forwarded headers are never trusted by this package. Raw errors, credentials, signed payloads and content are not logged.

## Move acceptance and limits

First import requires an online source with the exact freeze durably committed. The production verifier requires public HTTPS, validates every DNS answer, denies private/link-local/reserved/metadata addresses (including mapped IPv6 and mixed answers), pins the checked address, verifies the original TLS hostname, rejects redirects and limits DNS/response time and bytes. It sends no caller credentials. Source verification occurs outside the database transaction; destination state is rechecked under lock. Loopback tests inject an explicit verifier in code; there is no environment bypass.

After acceptance, the identical import retry and destination activity need no source. **Offline-first same-ID recovery remains unavailable.** A malicious or uncooperative host cannot be cryptographically forced to cooperate by this protocol. Export remains available from a cooperative frozen host; there is no automatic fork or unsafe source unfreeze. Check destination readiness before freezing.

The journal budgets are 1,200,000 bytes for ordinary activity, 1,440,000 for control operations and 1,500,000 for freeze/resume. Every acknowledgement also checks the actual public response and full archive plus maximum-sized resume against the 4 MB limit. The moderation/initial-move reserve is tested but finite. Deletion and movement do not reclaim journal capacity; there is no automatic compaction.

## Reproducible validation

    node --test packages/v3-network-protocol/test/*.test.mjs packages/v3-network-service/test/*.test.mjs
    node packages/v3-network-service/test/postgres.integration.mjs

The second command requires NETWORK_DATABASE_TEST_URL or GLANCE_DATABASE_INTEGRATION_URL pointing to a local dedicated glance_v3_ci/integration/proof database with this schema applied. It rejects remote/non-test targets. It covers replica conflicts, exact-once receipts, rollback, shared budgets, encrypted data, wrong-key readiness, public features, moves/return moves, stale import rejection and committed freeze recovery after abrupt termination of the API child. Records are synthetic and cleaned up by host origin. Do not stop/reset unrelated clusters or databases.

These tests do not certify database power loss, Google HA failover, backup restore, external cryptography review or public source publication. Restoring a pre-freeze snapshot can resurrect stale authority: production restore must fence writes until lineage and exactly one writer are verified. Private E2EE remains disabled pending separate MLS, device-lifecycle and external-review gates.
