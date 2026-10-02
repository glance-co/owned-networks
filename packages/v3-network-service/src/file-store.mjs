// SPDX-License-Identifier: Apache-2.0
// Development/reference store. Production uses the PostgreSQL implementation.
import { mkdir, open, readFile, rename, readdir } from 'node:fs/promises';
import { openSync, closeSync, unlinkSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { PROTOCOL, ProtocolError, replay } from '../../v3-network-protocol/src/index.mjs';

export async function createFileNetworkStore({directory,origin,now=()=>Date.now()}) {
  await mkdir(directory,{recursive:true});
  const lockPath=join(directory,'.writer-lock'),lock=openSync(lockPath,'wx',0o600);
  writeSync(lock,JSON.stringify({pid:process.pid}));
  let closed=false,serial=Promise.resolve();const states=new Map(),rates=new Map();
  const close=async()=>{if(closed)return;await serial;closed=true;closeSync(lock);unlinkSync(lockPath);};
  try {for(const name of await readdir(directory)) {
    if(!/^[a-f0-9-]{36}\.json$/.test(name))continue;
    const archive=JSON.parse(await readFile(join(directory,name),'utf8')),state=replay(archive.events);
    if(`${state.id}.json`!==name||state.host!==origin)throw new Error('stored_network_host_mismatch');
    states.set(state.id,state);
  }}catch(error){await close();throw error;}
  async function save(state) {
    const target=join(directory,`${state.id}.json`),temporary=join(directory,`${state.id}.${randomUUID()}.pending`);
    const handle=await open(temporary,'wx',0o600);
    try{await handle.writeFile(JSON.stringify({protocol:PROTOCOL,events:state.events}));await handle.sync();}finally{await handle.close();}
    await rename(temporary,target);states.set(state.id,state);
  }
  return {
    kind:'file',durableHandoff:false,
    async health(){if(closed)throw new Error('store_closed');return {store:'file',durableHandoff:false};},
    async get(id){return states.get(id)??null;},
    async list({afterId='',limit=20}={}){return {items:[...states.values()].filter(state=>state.id>afterId).sort((a,b)=>a.id.localeCompare(b.id)).slice(0,limit),hasMore:false};},
    async transaction(id,work){
      const job=serial.then(async()=>{if(closed)throw new Error('store_closed');const previous=states.get(id)??null;const result=await work(previous);if(result.state){if(!previous&&states.size>=1000)throw new ProtocolError('host_capacity');await save(result.state);}return result.result;});
      serial=job.catch(()=>{});return job;
    },
    async takeRate(key,limit,windowMs=60_000){
      const tick=Math.floor(now()/windowMs);
      if(rates.size>10000){for(const [id,value] of rates)if(value.tick<tick)rates.delete(id);if(rates.size>10000)throw new ProtocolError('service_busy');}
      const prior=rates.get(key),count=prior?.tick===tick?prior.count+1:1;rates.set(key,{tick,count});return count<=limit;
    },close,
  };
}
