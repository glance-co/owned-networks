// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { createNetworkServer } from '../src/server.mjs';
import { createIdentity,nextEvent,decodeEvent,signRead,reportEvidence } from '../../v3-network-protocol/src/index.mjs';
const close=server=>new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
const post=async(url,event)=>{const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({event})});return {status:response.status,data:await response.json()};};

test('public HTTP writes are idempotent and discovery/feed pages are revision fenced',async()=>{
  const probe=createServer();await new Promise(resolve=>probe.listen(0,'127.0.0.1',resolve));const port=probe.address().port;await close(probe);
  const directory=await mkdtemp(join(tmpdir(),'glance-public-http-')),origin=`http://127.0.0.1:${port}`;let clock=Date.now();
  const server=await createNetworkServer({directory,origin,now:()=>clock});await new Promise(resolve=>server.listen(port,'127.0.0.1',resolve));
  const owner=createIdentity(),member=createIdentity(),visitor=createIdentity();let state;
  const write=async(identity,action,data)=>{const compact=nextEvent(identity,state,action,data,new Date(clock));const result=await post(state?`${origin}/v1/networks/${state.id}/events`:`${origin}/v1/networks`,compact);assert.equal(result.status,200,JSON.stringify(result.data));state=result.data;return compact;};
  try{
    const genesis=await write(owner,'network.create',{name:'Public HTTP community',visibility:'public',host:origin,enrollment:'approval',displayName:'Owner'});
    const created=decodeEvent(genesis);assert.deepEqual(state.receipt,{eventId:created.event.eventId,sequence:1,digest:created.digest,replayed:false});
    await write(member,'member.request',{displayName:'Applicant'});assert.equal(state.pendingMembers.length,1);
    await write(owner,'member.approve',{actorId:member.actorId,role:'member'});assert.equal(state.members.find(value=>value.actorId===member.actorId).displayName,'Applicant');
    const first=await write(member,'post.create',{text:'First chronological post',parentId:null});
    await write(owner,'post.create',{text:'Second chronological post',parentId:null});
    await write(member,'post.create',{text:'Third chronological post',parentId:null});
    const page=await (await fetch(`${origin}/v1/networks/${state.id}/feed?kind=posts&limit=2`)).json();
    assert.deepEqual(page.page.ids,state.posts.slice(-2).reverse().map(value=>value.id));assert.ok(page.page.nextCursor);
    const second=await(await fetch(`${origin}/v1/networks/${state.id}/feed?kind=posts&limit=2&cursor=${page.page.nextCursor}`)).json();assert.deepEqual(second.page.ids,[state.posts[0].id]);assert.equal(second.page.nextCursor,null);
    const before=state.sequence;clock+=90_000;
    const replayed=await post(`${origin}/v1/networks/${state.id}/events`,first);assert.equal(replayed.status,200);assert.equal(replayed.data.receipt.replayed,true);assert.equal(replayed.data.sequence,before);assert.equal(replayed.data.receipt.digest,decodeEvent(first).digest);
    const stale=nextEvent(owner,state,'post.create',{text:'Expired unaccepted command',parentId:null},new Date(clock-90_000));assert.equal((await post(`${origin}/v1/networks/${state.id}/events`,stale)).data.error,'stale_event');
    await write(owner,'resource.create',{title:'Handbook',url:'https://example.org/handbook',description:'Public document'});
    assert.equal((await fetch(`${origin}/v1/networks/${state.id}/feed?kind=posts&limit=2&cursor=${page.page.nextCursor}`)).status,409);
    assert.equal((await fetch(`${origin}/v1/networks/${state.id}/feed?kind=constructor`)).status,400);
    const resource=state.resources[0];await write(visitor,'report.create',{targetKind:'resource',targetId:resource.id,reviewedText:reportEvidence(state,'resource',resource.id),reason:'Review the shared document',shareWithModerators:true});
    const queue=await fetch(`${origin}/v1/networks/${state.id}/reports`,{headers:{Authorization:`Bearer ${signRead(owner,state.id,'report.read',new Date(clock))}`}});assert.equal(queue.status,200);assert.equal((await queue.json()).proofs.filter(value=>value.includes('~')).length,1);
    const exported=await(await fetch(`${origin}/v1/networks/${state.id}/public-archive`)).json();assert.equal(exported.scope,'public');assert.equal(exported.events.some(value=>value.includes('~')),false);assert.deepEqual(exported.events,state.proofs);
    const discovered=await(await fetch(`${origin}/v1/networks?limit=1`)).json();assert.equal(discovered.networks[0].id,state.id);assert.equal(discovered.networks[0].proofs.some(value=>value.includes('~')),false);
    const health=await(await fetch(`${origin}/v1/health`)).json();assert.equal(health.privateE2EE,false);assert.equal(health.durableHandoff,false);
  }finally{await close(server);await rm(directory,{recursive:true,force:true});}
});
