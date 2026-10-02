// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { createNetworkServer } from '../src/server.mjs';
import { PROTOCOL, createIdentity, nextEvent, signRead,applyEvent } from '../../v3-network-protocol/src/index.mjs';
import { verifyLoopbackSourceForTests } from './source-proof-helper.mjs';
const close = server => new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
async function unusedPort(){const probe=createServer();await new Promise(resolve=>probe.listen(0,'127.0.0.1',resolve));const port=probe.address().port;await close(probe);return port;}
async function host(directory,port,options={}){const origin=`http://127.0.0.1:${port}`,server=await createNetworkServer({directory,origin,verifySourceFreeze:verifyLoopbackSourceForTests,...options});await new Promise(resolve=>server.listen(port,'127.0.0.1',resolve));return {origin,server};}
const post=async(url,payload)=>{const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});return {status:response.status,data:await response.json()};};

test('initial import confirms source freeze, then old host can be off; authority, identity, reports and clean restart survive',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'glance-owned-network-'));
  const first=await host(join(directory,'one'),await unusedPort()),second=await host(join(directory,'two'),await unusedPort());
  const owner=createIdentity(),member=createIdentity(),stranger=createIdentity();let firstClosed=false,secondClosed=false;
  try {
    const genesis=nextEvent(owner,null,'network.create',{name:'Moveable community',visibility:'public',host:first.origin});
    await assert.rejects(createNetworkServer({directory:join(directory,'one'),origin:first.origin}),/EEXIST/);
    const rejectedOrigin=await fetch(`${first.origin}/health`,{headers:{Origin:'https://unapproved.example'}});assert.equal(rejectedOrigin.status,403);
    let result=await post(`${first.origin}/v1/networks`,{event:genesis});assert.equal(result.status,200);let state=result.data;const id=state.id;
    const uncommitted=applyEvent(applyEvent(null,genesis),nextEvent(owner,state,'host.freeze',{destination:second.origin}));
    const rejectedFreeze=await post(`${second.origin}/v1/import`,{protocol:PROTOCOL,events:uncommitted.events,resume:nextEvent(owner,uncommitted,'host.resume',{host:second.origin})});
    assert.equal(rejectedFreeze.status,409);assert.equal(rejectedFreeze.data.error,'source_freeze_unconfirmed');
    assert.equal((await fetch(`${second.origin}/v1/networks/${id}`)).status,404,'unsigned host admission cannot be replaced by an offline owner freeze');
    const originalActor=state.owner;const route=`/v1/networks/${id}`;
    result=await post(`${first.origin}${route}/events`,{event:nextEvent(stranger,state,'post.create',{text:'Host cannot publish',parentId:null})});assert.equal(result.status,403);
    result=await post(`${first.origin}${route}/events`,{event:nextEvent(owner,state,'member.add',{actorId:member.actorId,publicKey:member.publicJwk,role:'member'})});assert.equal(result.status,200);state=result.data;
    const signedPost=nextEvent(member,state,'post.create',{text:'Independent public post',parentId:null});
    result=await post(`${first.origin}${route}/events`,{event:signedPost});assert.equal(result.status,200);state=result.data;
    const retry=await post(`${first.origin}${route}/events`,{event:signedPost});assert.equal(retry.status,200);assert.equal(retry.data.receipt.replayed,true);assert.equal(retry.data.sequence,state.sequence);
    const validReport=nextEvent(stranger,state,'report.create',{postId:state.posts[0].id,reviewedText:state.posts[0].text,reason:'Community review',shareWithModerators:true});
    assert.equal((await post(`${first.origin}${route}/events`,{event:validReport+'!'})).status,400,'noncanonical report sidecar must not poison the moderation journal');
    result=await post(`${first.origin}${route}/events`,{event:validReport});assert.equal(result.status,200);state=result.data;
    assert.equal('reports' in state,false);
    const reports=await fetch(`${first.origin}${route}/reports`,{headers:{Authorization:`Bearer ${signRead(owner,id,'report.read')}`}});assert.equal((await reports.json()).proofs.filter(proof=>proof.includes('~')).length,1);
    result=await post(`${first.origin}${route}/events`,{event:nextEvent(owner,state,'host.freeze',{destination:second.origin})});assert.equal(result.status,200);state=result.data;
    assert.equal((await post(`${first.origin}${route}/events`,{event:nextEvent(owner,state,'post.create',{text:'Cannot fork old host',parentId:null})})).status,409);
    const exportResponse=await fetch(`${first.origin}${route}/archive`,{headers:{Authorization:`Bearer ${signRead(owner,id,'archive.read')}`}});assert.equal(exportResponse.status,200);const archive=await exportResponse.json();
    const resume=nextEvent(owner,state,'host.resume',{host:second.origin});
    result=await post(`${second.origin}/v1/import`,{...archive,resume});assert.equal(result.status,201);state=result.data;
    await close(first.server);firstClosed=true;
    const retriedImport=await post(`${second.origin}/v1/import`,{...archive,resume});assert.equal(retriedImport.status,200);assert.equal(retriedImport.data.receipt.replayed,true,'accepted retry must not depend on the old host');
    assert.equal(state.id,id);assert.equal(state.owner,originalActor);assert.equal(state.posts[0].text,'Independent public post');
    result=await post(`${second.origin}${route}/events`,{event:nextEvent(member,state,'post.create',{text:'Written after move without Glance',parentId:null})});assert.equal(result.status,200);
    await close(second.server);secondClosed=true;
    const restarted=await host(join(directory,'two'),Number(new URL(second.origin).port));
    try {const response=await fetch(`${restarted.origin}${route}`);assert.equal(response.status,200);assert.equal((await response.json()).posts.length,2);
      assert.equal((await fetch(`${restarted.origin}${route}/archive`)).status,400);
      const failedPrivate=await post(`${restarted.origin}/v1/networks`,{event:nextEvent(owner,null,'network.create',{name:'Never plaintext private',visibility:'private',host:restarted.origin})});assert.equal(failedPrivate.status,503);assert.equal(failedPrivate.data.error,'private_e2ee_not_accepted');
      assert.equal(archive.protocol,PROTOCOL);
    } finally {await close(restarted.server);}
  } finally {if(!firstClosed)await close(first.server);if(!secondClosed)await close(second.server);await rm(directory,{recursive:true,force:true});}
});

test('an ordinary member cannot backdate deletion to reuse expired delegation; own-author and administrator rights remain valid',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'glance-delegation-expiry-'));
  const baseline=Date.now();let clock=baseline;
  const server=await host(directory,await unusedPort(),{now:()=>clock});
  const owner=createIdentity(),member=createIdentity();let state;
  const command=async(identity,action,data,issuedAt=clock)=>{
    const result=await post(state?`${server.origin}/v1/networks/${state.id}/events`:`${server.origin}/v1/networks`,{event:nextEvent(identity,state??null,action,data,new Date(issuedAt))});
    if(result.status===200)state=result.data;return result;
  };
  try{
    assert.equal((await command(owner,'network.create',{name:'Expiry regression',visibility:'public',host:server.origin})).status,200);
    assert.equal((await command(owner,'member.add',{actorId:member.actorId,publicKey:member.publicJwk,role:'member'})).status,200);
    assert.equal((await command(owner,'post.create',{text:'Owner post',parentId:null})).status,200);const ownerPost=state.posts.at(-1).id;
    assert.equal((await command(member,'post.create',{text:'Member post',parentId:null})).status,200);const memberPost=state.posts.at(-1).id;
    assert.equal((await command(owner,'delegation.grant',{actorId:member.actorId,publicKey:member.publicJwk,scopes:['post.delete'],expiresAt:new Date(baseline+1000).toISOString()})).status,200);
    const before=state.sequence;clock=baseline+2000;
    const denied=await command(member,'post.delete',{postId:ownerPost,reason:'Backdated within the 60-second freshness window'},baseline+500);
    assert.equal(denied.status,403);assert.equal(denied.data.error,'authority_denied');assert.equal(state.sequence,before);assert.equal(state.posts.some(post=>post.id===ownerPost),true);
    assert.equal((await command(member,'post.delete',{postId:memberPost,reason:'Independent author right'})).status,200);
    assert.equal((await command(owner,'member.add',{actorId:member.actorId,publicKey:member.publicJwk,role:'administrator'})).status,200);
    assert.equal((await command(member,'post.delete',{postId:ownerPost,reason:'Independent administrator right'})).status,200);
  }finally{await close(server.server);await rm(directory,{recursive:true,force:true});}
});
