// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash,createPrivateKey,sign } from 'node:crypto';
import { createIdentity, applyEvent, nextEvent, replay, signRead, authorizeRead, publicView, decodeEvent } from '../src/index.mjs';
const setup = () => { const owner = createIdentity(); return { owner, state: applyEvent(null,nextEvent(owner,null,'network.create',{name:'Community',visibility:'public',host:'https://first.example'})) }; };
const add = (state,identity,action,data) => applyEvent(state,nextEvent(identity,state,action,data));

test('private networks fail closed and require explicit public audience',()=>{
  const owner=createIdentity();
  for (const visibility of ['private',undefined,'encrypted']) assert.throws(()=>applyEvent(null,nextEvent(owner,null,'network.create',{name:'Private',visibility,host:'https://first.example'})),/private_e2ee_not_accepted|invalid_genesis/);
});
test('open enrollment requires a signed join and approval networks reject it',()=>{
  const {owner,state}=setup(),visitor=createIdentity();
  assert.throws(()=>add(state,visitor,'member.join',{}),/authority_denied/);
  let open=applyEvent(null,nextEvent(owner,null,'network.create',{name:'Open community',visibility:'public',enrollment:'open',host:'https://first.example'}));
  assert.throws(()=>add(open,visitor,'post.create',{text:'Before joining',parentId:null}),/authority_denied/);
  open=add(open,visitor,'member.join',{});open=add(open,visitor,'post.create',{text:'Joined using verified signature',parentId:null});
  assert.equal(open.members[visitor.actorId].role,'member');assert.equal(Object.keys(open.posts).length,1);
  open=add(open,owner,'member.remove',{actorId:visitor.actorId});assert.throws(()=>add(open,visitor,'member.join',{}),/authority_denied/);
});
test('cryptographic identity does not give host or founder community authority',()=>{
  const {owner,state}=setup(), founder=createIdentity();
  assert.throws(()=>add(state,founder,'post.create',{text:'Cannot publish',parentId:null}),/authority_denied/);
  assert.throws(()=>authorizeRead(state,signRead(founder,state.id,'archive.read'),'archive.read'),/authority_denied/);
  const tampered=state.events[0].slice(0,-4)+'AAAA'; assert.throws(()=>replay([tampered]),/invalid_signature/);
  assert.throws(()=>add(state,founder,'member.add',{actorId:founder.actorId,publicKey:founder.publicJwk,role:'administrator'}),/authority_denied/);
  assert.equal(owner.actorId,state.owner);
});
test('signed authority cannot target inherited object properties',()=>{
  const {owner,state}=setup();
  for(const actorId of ['constructor','__proto__','toString']){
    assert.throws(()=>add(state,owner,'owner.transfer',{actorId}),/authority_denied/);
    assert.throws(()=>add(state,owner,'member.remove',{actorId}),/authority_denied/);
    assert.throws(()=>add(state,owner,'delegation.revoke',{actorId}),/authority_denied/);
  }
  assert.equal(Object.prototype.role,undefined);
});
test('private report commitments randomize repeated data and reject malformed nonce even if correctly signed',()=>{
  let {owner,state}=setup();state=add(state,owner,'post.create',{text:'Repeated public evidence',parentId:null});
  const data={postId:Object.keys(state.posts)[0],reviewedText:'Repeated public evidence',reason:'privacy',shareWithModerators:true};
  const first=nextEvent(owner,state,'report.create',data),second=nextEvent(owner,state,'report.create',data);
  const payload=token=>JSON.parse(Buffer.from(token.split('.')[1],'base64url'));
  assert.notEqual(payload(first).data.sha256,payload(second).data.sha256);
  for(const nonce of ['',[], 'A'.repeat(42), 'A'.repeat(42)+'B']){
    const [jws,sidecar]=first.split('~'),header=jws.split('.')[0],event=payload(first);
    const wrapper=JSON.parse(Buffer.from(sidecar,'base64url'));wrapper.nonce=nonce;const body=Buffer.from(JSON.stringify(wrapper));
    event.data.sha256=createHash('sha256').update(body).digest('base64url');
    const input=`${header}.${Buffer.from(JSON.stringify(event)).toString('base64url')}`;
    const invalid=`${input}.${sign(null,Buffer.from(input),createPrivateKey({key:owner.privateJwk,format:'jwk'})).toString('base64url')}~${body.toString('base64url')}`;
    assert.throws(()=>decodeEvent(invalid),/invalid_report_commitment/);
  }
});
test('JWS and private sidecars require canonical base64url to prevent journal poisoning and digest malleability',()=>{
  const {owner,state}=setup();
  const compact=nextEvent(owner,state,'report.review',{reportId:'11111111-1111-4111-8111-111111111111',status:'resolved',reason:'Canonical test'});
  assert.throws(()=>decodeEvent(compact+'!'),/invalid_signature/);
  assert.throws(()=>decodeEvent(compact+'='),/invalid_signature/);
  const [jws,sidecar]=compact.split('~'),parts=jws.split('.');
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',last=parts[2].at(-1),index=alphabet.indexOf(last);
  assert.equal(index%16,0,'64-byte Ed25519 signatures have four zero trailing base64 pad bits');
  parts[2]=parts[2].slice(0,-1)+alphabet[index+1];
  assert.throws(()=>decodeEvent(parts.join('.')+'~'+sidecar),/invalid_signature/);
  assert.deepEqual(decodeEvent(compact).event.data,{reportId:'11111111-1111-4111-8111-111111111111',status:'resolved',reason:'Canonical test'});
});

test('public-key pad-bit aliases cannot poison Node-accepted journals that browsers reject',()=>{
  const {owner,state}=setup(),alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const alias={...owner.publicJwk,x:owner.publicJwk.x.slice(0,-1)+alphabet[alphabet.indexOf(owner.publicJwk.x.at(-1))+1]};
  assert.deepEqual(Buffer.from(alias.x,'base64url'),Buffer.from(owner.publicJwk.x,'base64url'));
  const signed=nextEvent(owner,state,'member.join',{}),payload=JSON.parse(Buffer.from(signed.split('.')[1],'base64url'));
  payload.actorId='urn:glance:actor:'+createHash('sha256').update(JSON.stringify({crv:alias.crv,kty:alias.kty,x:alias.x})).digest('base64url');
  const input=Buffer.from(JSON.stringify({alg:'EdDSA',typ:payload.protocol,jwk:alias})).toString('base64url')+'.'+Buffer.from(JSON.stringify(payload)).toString('base64url');
  const compact=input+'.'+sign(null,Buffer.from(input),createPrivateKey({key:owner.privateJwk,format:'jwk'})).toString('base64url');
  assert.throws(()=>decodeEvent(compact),/invalid_public_key/);
  assert.throws(()=>add(state,owner,'member.add',{actorId:payload.actorId,publicKey:alias,role:'member'}),/invalid_public_key/);
});

test('valid signatures over malformed UTF-8 cannot poison browser history or private report queues',()=>{
  const {owner,state}=setup();
  const badUtf8=value=>{const bytes=Buffer.from(value),offset=bytes.indexOf('REPLACE');assert.ok(offset>=0);return Buffer.concat([bytes.subarray(0,offset),Buffer.from([0xff]),bytes.subarray(offset+7)]);};
  const signParts=(header,payload,sidecar)=>{const input=header+'.'+payload;return input+'.'+sign(null,Buffer.from(input),createPrivateKey({key:owner.privateJwk,format:'jwk'})).toString('base64url')+(sidecar?'~'+sidecar:'');};
  const named=nextEvent(owner,state,'member.profile',{displayName:'REPLACE'}).split('.');
  const malformedPayload=badUtf8(Buffer.from(named[1],'base64url').toString('utf8')).toString('base64url');
  assert.throws(()=>decodeEvent(signParts(named[0],malformedPayload)),/invalid_signature/);
  const report=nextEvent(owner,state,'report.create',{postId:'11111111-1111-4111-8111-111111111111',reviewedText:'Evidence',reason:'REPLACE',shareWithModerators:true});
  const [jws,sidecar]=report.split('~'),parts=jws.split('.'),payload=JSON.parse(Buffer.from(parts[1],'base64url'));
  const malformedSidecar=badUtf8(Buffer.from(sidecar,'base64url').toString('utf8'));payload.data.sha256=createHash('sha256').update(malformedSidecar).digest('base64url');
  assert.throws(()=>decodeEvent(signParts(parts[0],Buffer.from(JSON.stringify(payload)).toString('base64url'),malformedSidecar.toString('base64url'))),/invalid_signature/);
});
test('delegation is scoped, expires, and revocation takes effect immediately',()=>{
  let {owner,state}=setup();const delegate=createIdentity();
  state=add(state,owner,'post.create',{text:'Visible post',parentId:null});const postId=Object.keys(state.posts)[0];
  state=add(state,owner,'delegation.grant',{actorId:delegate.actorId,publicKey:delegate.publicJwk,scopes:['report.read'],expiresAt:new Date(Date.now()+60_000).toISOString()});
  authorizeRead(state,signRead(delegate,state.id,'report.read'),'report.read');
  assert.throws(()=>add(state,delegate,'post.delete',{postId,reason:'No delete grant'}),/authority_denied/);
  assert.throws(()=>authorizeRead(state,signRead(delegate,state.id,'report.read',new Date(Date.now()+120_000)),'report.read',Date.now()+120_000),/authority_denied/);
  state=add(state,owner,'delegation.revoke',{actorId:delegate.actorId});
  assert.throws(()=>authorizeRead(state,signRead(delegate,state.id,'report.read'),'report.read'),/authority_denied/);
  assert.equal(Object.keys(state.posts).length,1);
});
test('reports require reviewed content, public projection does not disclose reports, and membership removal fences publishing',()=>{
  let {owner,state}=setup();const member=createIdentity(), visitor=createIdentity();
  state=add(state,owner,'member.add',{actorId:member.actorId,publicKey:member.publicJwk,role:'member'});
  state=add(state,member,'post.create',{text:'Public content',parentId:null});const postId=Object.keys(state.posts)[0];
  assert.throws(()=>add(state,visitor,'report.create',{postId,reviewedText:'Wrong copy',reason:'Privacy',shareWithModerators:true}),/invalid_report/);
  state=add(state,visitor,'report.create',{postId,reviewedText:'Public content',reason:'Privacy',shareWithModerators:true});
  assert.equal('reports' in publicView(state),false);
  assert.throws(()=>authorizeRead(state,signRead(member,state.id,'report.read'),'report.read'),/authority_denied/);
  state=add(state,owner,'member.remove',{actorId:member.actorId});
  assert.throws(()=>add(state,member,'post.create',{text:'Removed',parentId:null}),/authority_denied/);
  assert.deepEqual(replay(state.events),state);
});
test('handoff binds destination, rejects history edits and prevents source resume',()=>{
  let {owner,state}=setup();state=add(state,owner,'host.freeze',{destination:'https://second.example'});
  assert.throws(()=>add(state,owner,'post.create',{text:'Old host',parentId:null}),/network_frozen/);
  const resume=nextEvent(owner,state,'host.resume',{host:'https://second.example'});
  assert.throws(()=>applyEvent(state,resume),/network_frozen/);
  const moved=applyEvent(state,resume,{importing:true});assert.equal(moved.owner,state.owner);assert.equal(moved.id,state.id);
  assert.equal(moved.host,'https://second.example');assert.deepEqual(replay(moved.events),moved);
  assert.throws(()=>replay([moved.events[0],moved.events[2]]),/revision_conflict/);
});
