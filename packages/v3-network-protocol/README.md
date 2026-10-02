# Public owned-network protocol

Apache-2.0 public network implementation using glance-owned-network/1. This is a versioned implementation, not a ratified or independently certified interoperability standard. Private creation fails closed with private_e2ee_not_accepted; federation and binding governance are deferred. No Glance login, Gmail, founder authority or deployment dependency is required.

Each command is an RFC 7515 compact JWS authenticated with RFC 8037 Ed25519. An actor is an RFC 7638 JWK thumbprint independent of email, account and host. Canonical base64url is required for keys, JWS parts and private sidecars. A signature proves key control; a display name is self-selected and is not a verified email identity. Owners choose open enrollment or approval; older journals without a policy remain approval-only.

## Public features

| Signed actions | Authority and behavior |
| --- | --- |
| network.create | Owner-signed explicit public genesis, optional display name and open/approval enrollment |
| member.join, member.request, member.profile | Signed open join or public named approval request; a current member edits their own name |
| member.approve, member.reject, member.add, member.role, member.remove | Owner manages membership and administrator roles; approval uses the applicant's already signed key |
| owner.transfer, member.leave | Owner transfers to an existing member; others may leave; an owner transfers before leaving |
| post.create, post.delete | Member discussions/replies; author, administrator or exact post.delete delegate removes a current projection |
| resource.create, resource.delete | Member title, URL and description; author/administrator removal |
| event.create, event.cancel, event.rsvp | Future events, author/administrator cancellation, each member's latest public RSVP |
| poll.create, poll.vote, poll.close | Advisory polls, 2–8 distinct options, one latest public choice per member, author/administrator closure |
| delegation.grant, delegation.revoke | Owner grants a key exact post.delete and/or report.read scopes for at most 30 days |
| report.create, report.review | Visitors report exact reviewed public evidence with sharing consent; current owner/administrators review |
| host.freeze, host.resume | Owner binds source freeze to one destination; first import also verifies source commitment |

Polls never execute governance or ownership changes. Removed keys cannot immediately rejoin. There is no founder, hosting-operator or Glance content authority. A report.read delegate may read but cannot review a report. Revoked/expired authority is fenced at admission; time-sensitive commands must be valid both at admission and signed time, preventing backdating and future-skew histories that cannot replay.

Resources allow titles of 120 characters, HTTP/HTTPS URLs without credentials of 2,000 characters, and descriptions of 2,000 characters. Events allow titles of 120, descriptions of 2,000 and locations of 300 characters; starts must be future and within 366 days, duration at most 31 days. Poll questions allow 300 characters, each option 120, closure within 30 days.

All content, profiles, membership requests, RSVP responses and individual poll choices are public and exportable. Removing a current projection does not erase signed history, previous exports or backups. Leaving does not erase past contributions. Do not put private content in public actions.

## Reports and hosting

Reports commit a random 256-bit nonce and exact private payload with SHA-256 in the signed event. A private sidecar follows ~; the chain digest covers the JWS, excluding that sidecar. Public proofs omit sidecars but retain report occurrence, signer and timing. Authorized readers verify commitments before displaying evidence.

Reporting discussions, resources, events and polls requires exact reviewed evidence and explicit sharing consent. Retained reports are available to currently authorized community administrators and active report-read delegates, including future appointments. The UI must disclose that audience before submission. A changed authority revision invalidates an older signed request. Reports retain evidence if the current source projection is removed.

Transport limits, TLS, resource protection and database consistency are hosting security, not community content powers. Host storage encryption is not E2EE: the host processes authorized reports and encrypts the stored journal using its own storage key.

## Verification and movement

The journal links exact sequences and previous JWS digests. Replay verifies every signature, authority transition and link. Clients derive their own projection from verified history and fence previously observed prefixes. Unsigned host assertions do not grant authority. Chronological pages use creation sequence and an exact signed revision; a changed revision requires restarting pagination. Discovery verifies each returned network but cannot prove a host listed every network.

A public archive contains public proofs only, including removed content and report metadata. An owner archive also contains consented private report sidecars and must be handled accordingly. When reports exist, only the latter is a complete migration archive. Archives are verified by the client and destination.

**First import requires the source online over public HTTPS with a matching durably committed freeze.** The destination checks the source /handoff response, including signed ID, source, sequence, head, frozen state and exact destination. Production resolution rejects private, link-local, metadata and reserved addresses, including mixed DNS answers. TLS connects to the checked address with certificate-name verification, no redirect, no caller credentials and bounded time/bytes. Destination state is rechecked under its write lock.

An offline owner-signed freeze alone is insufficient. After an import is accepted, its exact retry and ongoing destination operation need no source host. A return move must extend the prior host's retained frozen prefix. Verify destination readiness before freezing.

A malicious/uncooperative source cannot be forced to be truthful or available by this protocol. Offline-first same-ID recovery remains unresolved pending pinned host attestations or another reviewed mechanism. There is no automatic identity fork, replacement or source unfreeze. Export remains available from a cooperative frozen source. Endpoint discovery still needs a trusted link/directory; an old-host hint is not an independent identity directory.

## Capacity and remaining gates

Ordinary commands stop at **1,200,000 signed-journal bytes**; control actions reserve up to **1,440,000**, and freeze/resume up to **1,500,000**. Tests fill ordinary capacity with visitor reports and still review, revoke, remove and perform an initial move. Each acknowledgement additionally checks actual public-response and archive-plus-resume sizes against the 4 MB transport limit. Reserves are finite, not unlimited compaction. Movement and deletion do not reset history capacity. Export remains available at capacity.

The [browser client](../v3-network-client/README.md) supplies device custody and encrypted key backup/import. Glance key reset, identity rotation, independent discovery, trusted-device recovery, automatic compaction and verified-person anti-Sybil enrollment are not supplied by this protocol. Private E2EE remains gated on MLS, durable device lifecycle and qualified external review; public signatures and storage encryption do not pass those gates.

Run the synthetic protocol/service tests on Node 24.14.1:

    node --test packages/v3-network-protocol/test/*.test.mjs packages/v3-network-service/test/*.test.mjs

The service also provides actual PostgreSQL multi-replica and abrupt API-process recovery tests. Two hosts running this implementation demonstrate independent operation, not cross-implementation interoperability. Operational restore/HA acceptance and public source publication remain separate release work.

Standards: [JWS](https://www.rfc-editor.org/rfc/rfc7515), [JWK thumbprints](https://www.rfc-editor.org/rfc/rfc7638), [EdDSA for JOSE](https://www.rfc-editor.org/rfc/rfc8037), [MLS](https://www.rfc-editor.org/rfc/rfc9420).
