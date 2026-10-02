import type { NetworkStore } from './server.mjs';
export function createPostgresNetworkStore(options:{connectionString:string;origin:string;storageKey:string;maxConnections?:number;pool?:unknown}):Promise<NetworkStore>;
