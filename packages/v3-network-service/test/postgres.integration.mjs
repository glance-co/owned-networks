// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { createHash,randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { Pool } from 'pg';
import { createPostgresNetworkStore } from '../src/postgres-store.mjs';
import { createNetworkServer } from '../src/server.mjs';
import { verifyLoopbackSourceForTests } from './source-proof-helper.mjs';
import { createIdentity,nextEvent,signRead,decodeEvent } from '../../v3-network-protocol/src/index.mjs';

const connectionString=process.env.NETWORK_DATABASE_TEST_URL??process.env.GLANCE_DATABASE_INTEGRATION_URL;
if(!connectionString)throw new Error('NETWORK_DATABASE_TEST_URL or GLANCE_DATABASE_INTEGRATION_URL is required');
const target=new URL(connectionString);
if(!['postgres:','postgresql:'].includes(target.protocol)||!['127.0.0.1','localhost'].includes(target.hostname)||target.search||target.hash||!/^\/glance_v3_(ci|integration|proof)(_[a-z0-9_]+)?$/.test(target.pathname))throw new Error('dedicated_local_database_required');
const storageKey='synthetic-owned-network-storage-key-for-tests-only',pool=new Pool({connectionString,max:4});
const close=server=>new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
async function port(){const probe=createServer();await new Promise(resolve=>probe.listen(0,'127.0.0.1',resolve));const result=probe.address().port;await close(probe);return result;}
const origins=[`http://127.0.0.1:${await port()}`,`http://127.0.0.1:${await port()}`,`http://127.0.0.1:${await port()}`];
const stores=[],servers=[];let child;
async function replica(origin,listenPort=Number(new URL(origin).port)){const store=await createPostgresNetworkStore({connectionString,origin,storageKey,maxConnections:2});stores.push(store);const server=await createNetworkServer({store,origin,verifySourceFreeze:verifyLoopbackSourceForTests});servers.push(server);await new Promise(resolve=>server.listen(listenPort,'127.0.0.1',resolve));return {store,server,url:`http://127.0.0.1:${listenPort}`};}
const request=async(url,payload)=>{const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});return {status:response.status,data:await response.json()};};
try{
  const first=await replica(origins[0]),second=await replica(origins[0],await port()),destination=await replica(origins[1]);
  const owner=createIdentity(),member=createIdentity(),outsider=createIdentity();let state;
  const write=async(identity,action,data,base=first.url)=>{const event=nextEvent(identity,state,action,data);const result=await request(`${base}${state?`/v1/networks/${state.id}/events`:'/v1/networks'}`,{event});assert.equal(result.status,200,JSON.stringify(result.data));state=result.data;return event;};
  await write(owner,'network.create',{name:'Synthetic transactional community',visibility:'public',host:origins[0],enrollment:'open'});
  const id=state.id,route=`/v1/networks/${id}`;
  await write(member,'member.join',{displayName:'Synthetic member'});
  const left=nextEvent(owner,state,'post.create',{text:'Concurrent owner proposal',parentId:null}),right=nextEvent(member,state,'post.create',{text:'Concurrent member proposal',parentId:null});
  const race=await Promise.all([request(first.url+route+'/events',{event:left}),request(second.url+route+'/events',{event:right})]);
  assert.deepEqual(race.map(row=>row.status).sort(),[200,409]);state=race.find(row=>row.status===200).data;
  const accepted=nextEvent(member,state,'post.create',{text:'Exactly once across replicas',parentId:null});
  const retries=await Promise.all([request(first.url+route+'/events',{event:accepted}),request(second.url+route+'/events',{event:accepted})]);
  assert.equal(retries.every(row=>row.status===200),true);assert.deepEqual(retries.map(row=>row.data.receipt.replayed).sort(),[false,true]);assert.equal(retries[0].data.sequence,retries[1].data.sequence);state=retries[0].data;
  await write(owner,'resource.create',{title:'Portable resource',url:'https://example.org/resource',description:'Survives movement'});
  await write(member,'event.create',{title:'Future event',description:'Synthetic gathering',startsAt:new Date(Date.now()+3600000).toISOString(),endsAt:new Date(Date.now()+7200000).toISOString(),location:'Synthetic venue'});
  const calendarId=state.calendarEvents[0].id;await write(owner,'event.rsvp',{eventId:calendarId,response:'going'});
  await write(owner,'poll.create',{question:'Advisory preference',options:['One','Two'],closesAt:new Date(Date.now()+3600000).toISOString()});const pollId=state.polls[0].id;
  await write(member,'poll.vote',{pollId,optionIndex:1});
  await write(outsider,'report.create',{postId:state.posts[0].id,reviewedText:state.posts[0].text,reason:'SYNTHETIC PRIVATE REPORT NOT SQL PLAINTEXT',shareWithModerators:true});
  const stored=await pool.query('SELECT "journalCiphertext" FROM "OwnedNetwork" WHERE "host"=$1 AND "id"=$2',[origins[0],id]);assert.equal(stored.rows[0].journalCiphertext.includes('SYNTHETIC PRIVATE REPORT'),false);assert.equal(stored.rows[0].journalCiphertext.includes('Portable resource'),false);
  await assert.rejects(createPostgresNetworkStore({connectionString,origin:origins[0],storageKey:'incorrect-synthetic-storage-key-for-tests-only'}),'wrong key cannot pass readiness');
  const beforeRollback=await first.store.get(id);
  await assert.rejects(first.store.transaction(id,async previous=>({state:{...previous,frozen:true},result:null})),/OwnedNetwork_frozen_destination/);
  assert.equal((await second.store.get(id)).head,beforeRollback.head);
  const rateKey=createHash('sha256').update(randomUUID()).digest('hex');const budgets=await Promise.all(Array.from({length:10},(_,index)=>(index%2?first.store:second.store).takeRate(rateKey,3,3600000)));assert.equal(budgets.filter(Boolean).length,3);
  await write(owner,'host.freeze',{destination:origins[1]});const frozen=state;
  const denied=await request(second.url+route+'/events',{event:nextEvent(member,state,'post.create',{text:'Stale replica must not write after freeze',parentId:null})});assert.equal(denied.status,409);assert.equal(denied.data.error,'network_frozen');
  const exported=await fetch(first.url+route+'/archive',{headers:{Authorization:`Bearer ${signRead(owner,id,'archive.read')}`}});assert.equal(exported.status,200);const archive=await exported.json();
  const resume=nextEvent(owner,state,'host.resume',{host:origins[1]});const imported=await request(destination.url+'/v1/import',{...archive,resume});assert.equal(imported.status,201);state=imported.data;
  assert.equal(state.resources.length,1);assert.equal(state.calendarEvents[0].rsvps[owner.actorId].response,'going');assert.equal(state.polls[0].votes[member.actorId].optionIndex,1);assert.equal(state.owner,owner.actorId);
  const duplicateImport=await request(destination.url+'/v1/import',{...archive,resume});assert.equal(duplicateImport.status,200);assert.equal(duplicateImport.data.receipt.replayed,true);
  const recovered=await createPostgresNetworkStore({connectionString,origin:origins[0],storageKey});stores.push(recovered);assert.equal((await recovered.get(id)).head,frozen.head);assert.equal((await recovered.get(id)).frozen,true);
  await write(member,'post.create',{text:'Publishing at independently addressed destination',parentId:null},destination.url);
  // A move back must prove it extends the frozen source prefix; stale imports
  // cannot replace this newer incarnation after it resumes.
  await write(owner,'host.freeze',{destination:origins[0]},destination.url);
  const backArchive=await(await fetch(destination.url+route+'/archive',{headers:{Authorization:`Bearer ${signRead(owner,id,'archive.read')}`}})).json();
  const back=await request(first.url+'/v1/import',{...backArchive,resume:nextEvent(owner,state,'host.resume',{host:origins[0]})});assert.equal(back.status,201);state=back.data;
  assert.equal((await second.store.get(id)).frozen,false);assert.equal((await second.store.get(id)).head,state.head);
  const staleImport=await request(destination.url+'/v1/import',{...archive,resume:nextEvent(owner,frozen,'host.resume',{host:origins[1]})});assert.equal(staleImport.status,400);assert.equal(staleImport.data.error,'invalid_handoff');
  assert.equal((await request(first.url+'/v1/networks',{event:nextEvent(owner,null,'network.create',{name:'Must not become plaintext',visibility:'private',host:origins[0]})})).status,503);

  child=spawn(process.execPath,['packages/v3-network-service/test/postgres-child.mjs'],{cwd:process.cwd(),env:{...process.env,NETWORK_DATABASE_TEST_URL:connectionString,NETWORK_TEST_ORIGIN:origins[2]},windowsHide:true,stdio:['ignore','pipe','pipe']});
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('child_start_timeout')),15000);child.stdout.on('data',chunk=>{if(chunk.toString().includes('network-child-ready')){clearTimeout(timer);resolve();}});child.once('exit',()=>{clearTimeout(timer);reject(new Error('child_exited_before_ready'));});child.once('error',reject);});
  const crashOwner=createIdentity();let crash=(await request(origins[2]+'/v1/networks',{event:nextEvent(crashOwner,null,'network.create',{name:'Crash acknowledgement',visibility:'public',host:origins[2]})}));assert.equal(crash.status,200);
  crash=await request(`${origins[2]}/v1/networks/${crash.data.id}/events`,{event:nextEvent(crashOwner,crash.data,'host.freeze',{destination:origins[1]})});assert.equal(crash.status,200);
  const exit=once(child,'exit');child.kill();await exit;child=undefined;
  const afterCrash=await createPostgresNetworkStore({connectionString,origin:origins[2],storageKey});stores.push(afterCrash);assert.equal((await afterCrash.get(crash.data.id)).head,crash.data.head);assert.equal((await afterCrash.get(crash.data.id)).frozen,true);
  console.log('PostgreSQL owned networks passed: cross-replica CAS, exact-once receipts, rollback, shared rates, encrypted journal/wrong-key readiness, public resources/events/RSVP/advisory polls, freeze fencing, portable move/back, stale-import rejection and abrupt API-process freeze recovery. PostgreSQL crash/HA restore acceptance remains separate.');
}finally{
  if(child){const exit=once(child,'exit');child.kill();await exit;}
  for(const server of servers)await close(server);
  for(const store of stores)await store.close();
  await pool.query('DELETE FROM "OwnedNetwork" WHERE "host"=ANY($1::text[])',[origins]);await pool.end();
}
