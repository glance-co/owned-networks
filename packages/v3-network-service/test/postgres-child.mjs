// SPDX-License-Identifier: Apache-2.0
// Synthetic integration-test child. The parent kills this process after the
// freeze acknowledgement to test recovery without graceful API cleanup.
import { createPostgresNetworkStore } from '../src/postgres-store.mjs';
import { createNetworkServer } from '../src/server.mjs';
const connectionString=process.env.NETWORK_DATABASE_TEST_URL,origin=process.env.NETWORK_TEST_ORIGIN;
const target=new URL(connectionString);
if(!['127.0.0.1','localhost'].includes(target.hostname)||!/^\/glance_v3_(ci|integration|proof)(_[a-z0-9_]+)?$/.test(target.pathname))throw new Error('dedicated_database_required');
const store=await createPostgresNetworkStore({connectionString,origin,storageKey:'synthetic-owned-network-storage-key-for-tests-only'});
const server=await createNetworkServer({store,origin});await new Promise(resolve=>server.listen(Number(new URL(origin).port),'127.0.0.1',resolve));
process.stdout.write('network-child-ready\n');
