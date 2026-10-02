// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EventEmitter } from 'node:events';
import { createIdentity,nextEvent,applyEvent,publicView,PROTOCOL } from '../../v3-network-protocol/src/index.mjs';
import { isPublicAddress,resolvePublicSource,assertCommittedSource,verifySourceFreeze } from '../src/source-proof.mjs';

test('source proof rejects metadata/private/mapped/reserved destinations and mixed DNS before any connection',async()=>{
  for(const address of ['127.0.0.1','10.0.0.1','172.16.0.1','192.168.0.1','169.254.169.254','100.100.100.200','168.63.129.16','0.0.0.0','224.0.0.1','192.0.2.1','::1','::','fc00::1','fe80::1','::ffff:127.0.0.1','::ffff:169.254.169.254','64:ff9b::a00:1','2001:db8::1'])assert.equal(isPublicAddress(address),false,address);
  assert.equal(isPublicAddress('8.8.8.8'),true);assert.equal(isPublicAddress('2001:4860:4860::8888'),true);
  for(const origin of ['http://example.org','https://127.0.0.1','https://[::1]','https://user:password@example.org'])await assert.rejects(resolvePublicSource(origin),/source_verification_unavailable/);
  await assert.rejects(resolvePublicSource('https://source.example',{resolve:async()=>[{address:'8.8.8.8',family:4},{address:'10.0.0.1',family:4}]}),/source_verification_unavailable/);
});

const frozen=()=>{const owner=createIdentity();let state=applyEvent(null,nextEvent(owner,null,'network.create',{name:'Proof fixture',host:'https://source.example',visibility:'public'}));state=applyEvent(state,nextEvent(owner,state,'host.freeze',{destination:'https://destination.example'}));return state;};
test('a source proof must match the exact signed committed freeze and durable store claim',async()=>{
  const state=frozen(),value={protocol:PROTOCOL,durableHandoff:true,network:publicView(state)};
  await assertCommittedSource(state,'https://destination.example',value);
  await assert.rejects(assertCommittedSource(state,'https://destination.example',{...value,durableHandoff:false}),/source_verification_unavailable/);
  await assert.rejects(assertCommittedSource(state,'https://destination.example',{...value,network:{...value.network,frozen:false}}),/source_freeze_unconfirmed/);
  await assert.rejects(assertCommittedSource(state,'https://other.example',value),/source_freeze_unconfirmed/);
  await assert.rejects(assertCommittedSource({...state,head:'x'.repeat(43)},'https://destination.example',value),/source_freeze_unconfirmed/);
});

test('HTTPS handoff requests pin the checked address, validate TLS names and reject redirects/oversize responses',async()=>{
  const state=frozen(),value={protocol:PROTOCOL,durableHandoff:true,network:publicView(state)};let lookups=0,requests=0;
  const resolve=async()=>{lookups++;return [{address:'8.8.8.8',family:4}];};
  const transport=(status=200,payload=JSON.stringify(value))=>(options,callback)=>{
    requests++;assert.equal(options.rejectUnauthorized,true);assert.equal(options.servername,'source.example');assert.equal(options.agent,false);assert.equal(options.autoSelectFamily,false);assert.equal(options.headers.Authorization,undefined);
    options.lookup('source.example',{},(error,address,family)=>{assert.equal(error,null);assert.equal(address,'8.8.8.8');assert.equal(family,4);});
    const request=new EventEmitter();request.destroy=()=>{};request.end=()=>queueMicrotask(()=>{const response=new EventEmitter();response.statusCode=status;response.headers={'content-type':'application/json',location:'https://169.254.169.254'};response.destroy=()=>{};callback(response);response.emit('data',Buffer.from(payload));response.emit('end');});return request;
  };
  await verifySourceFreeze(state,'https://destination.example',{resolve,requestHttps:transport()});assert.equal(lookups,1);assert.equal(requests,1);
  await assert.rejects(verifySourceFreeze(state,'https://destination.example',{resolve,requestHttps:transport(302)}),/source_verification_unavailable/);assert.equal(requests,2,'redirect must not cause a second connection');
  await assert.rejects(verifySourceFreeze(state,'https://destination.example',{resolve,requestHttps:transport(200,'x'.repeat(4_000_001))}),/source_verification_unavailable/);
});
