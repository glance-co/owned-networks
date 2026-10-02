// SPDX-License-Identifier: Apache-2.0
import { resolve } from 'node:path';
import { createNetworkServer } from './server.mjs';
import { createPostgresNetworkStore } from './postgres-store.mjs';
const port = Number(process.env.PORT ?? 3015);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid_port');
const origin = process.env.NETWORK_ORIGIN ?? `http://127.0.0.1:${port}`;
const webOrigins=(process.env.NETWORK_WEB_ORIGINS??'').split(',').map(value=>value.trim()).filter(Boolean);
if(process.env.NODE_ENV==='production'&&!process.env.NETWORK_DATABASE_URL)throw new Error('production_network_database_required');
const store=process.env.NETWORK_DATABASE_URL?await createPostgresNetworkStore({connectionString:process.env.NETWORK_DATABASE_URL,origin,storageKey:process.env.NETWORK_STORAGE_KEY}):undefined;
const server = await createNetworkServer({ store,directory: resolve(process.env.NETWORK_DATA_DIRECTORY ?? './network-data'), origin, webOrigins });
server.listen(port,process.env.NETWORK_BIND_ADDRESS ?? '127.0.0.1',()=>{ console.log(`Owned network host listening on port ${port}; private E2EE disabled; ${store?'PostgreSQL':'development file'} storage.`); });
for (const signal of ['SIGTERM','SIGINT']) process.once(signal,()=>server.close(()=>{process.exitCode=0;}));
