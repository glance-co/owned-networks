# Glance owned-network reference

Apache-2.0 public-network protocol, browser signing/recovery client and independent Node/PostgreSQL host. This is experimental reference software, not a stable protocol or an independently audited production release. Private MLS networks and federation are unavailable. No Glance founder credentials, Gmail, app login, private application code or Glance-hosted service is required.

Use Node 24.14.1 and npm 11. Run `npm ci`, then `npm test` for the compatibility and authority suite. `npm start` starts a loopback file-backed development host on port 3015. For durable PostgreSQL hosting, apply `schema.sql` to a dedicated operator database and configure `NETWORK_DATABASE_URL`, `NETWORK_STORAGE_KEY` (at least 32 bytes), `NETWORK_ORIGIN` and `NETWORK_WEB_ORIGINS`. Supply secrets privately; never commit them. The file store is not accepted as production migration authority.

The application signing key belongs to its user. Server storage encryption is distinct from end-to-end encryption: public history is public and the host can process deliberately submitted community reports. Membership, administration and moderation depend on signed community grants, never Glance founder status. See each package README for transport limits, report metadata, recovery, public-history deletion limits and handoff requirements.

A first migration requires the source's committed freeze to be verified before the destination accepts writes. The destination subsequently operates independently with the source offline. Uncooperative/offline-first same-identity migration and independent MLS review remain open work; do not claim those guarantees from this release.

Source revision: `e7ba2c45f84c5aaf01f52770ec87e96c029678e5`. `SOURCE-MANIFEST.json` hashes every included source and generated distribution file. Remaining Glance application code is not included or relicensed. Third-party dependencies retain their respective upstream licenses.
