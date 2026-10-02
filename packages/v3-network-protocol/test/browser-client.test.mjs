// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { applyEvent, authorizeRead, publicView, actorId as referenceActorId } from '../src/index.mjs';
import { actorId, createIdentity, exportIdentity, importIdentity, signCommand, signRead, validateHost, verifyNetworkView, readNetwork, writeNetwork, importNetwork, readReports, discoverNetworks, readFeed, pageNetworkFeed, prepareNetworkWrite, prepareNetworkImport, submitNetworkWrite, reconcileNetworkWrite } from '../../v3-network-client/src/index.mjs';

test('WebCrypto identity signs standard JWS accepted by independent Node verifier',async()=>{
  const identity=await createIdentity();
  assert.equal(await actorId(identity.publicJwk),referenceActorId(identity.publicJwk));
  const genesis=await signCommand(identity,null,'network.create',{name:'Browser participant',visibility:'public',host:'https://independent.example'});
  const state=applyEvent(null,genesis);assert.equal(state.owner,identity.actorId);
  authorizeRead(state,await signRead(identity,state.id,'archive.read'),'archive.read');
  assert.equal(identity.privateKey.type,'private');assert.equal('privateJwk' in identity,false);
});

test('directory accepts a byte-limited short page only with its exact last verified network cursor',async()=>{
  const owner=await createIdentity(),host='https://directory-proof.example';
  const first=applyEvent(null,await signCommand(owner,null,'network.create',{name:'First directory network',visibility:'public',host}));
  const cursor=Buffer.from(JSON.stringify({version:1,afterId:first.id})).toString('base64url'),originalFetch=globalThis.fetch;
  try{globalThis.fetch=async()=>Response.json({networks:[publicView(first)],nextCursor:cursor});
    const page=await discoverNetworks(host,{limit:20});assert.equal(page.networks.length,1);assert.equal(page.nextCursor,cursor);
    globalThis.fetch=async()=>Response.json({networks:[],nextCursor:cursor});await assert.rejects(discoverNetworks(host),/directory cursor/);
    globalThis.fetch=async()=>Response.json({networks:[publicView(first)],nextCursor:Buffer.from(JSON.stringify({version:1,afterId:crypto.randomUUID()})).toString('base64url')});await assert.rejects(discoverNetworks(host),/directory cursor/);
  }finally{globalThis.fetch=originalFetch;}
});
test('encrypted identity backup survives a fresh import without disclosing a private JWK',async()=>{
  const identity=await createIdentity(),passphrase='synthetic long backup passphrase';
  const backup=await exportIdentity(identity,passphrase);
  assert.equal(backup.includes(identity.publicJwk.x),false);assert.equal(backup.includes('"d"'),false);assert.equal(backup.includes(passphrase),false);
  const restored=await importIdentity(backup,passphrase);assert.equal(restored.actorId,identity.actorId);
  const state=applyEvent(null,await signCommand(restored,null,'network.create',{name:'Restored identity',visibility:'public',host:'https://independent.example'}));assert.equal(state.owner,identity.actorId);
  await assert.rejects(importIdentity(backup,'wrong synthetic passphrase'),/could not be unlocked/);
  const tampered=JSON.parse(backup);tampered.ciphertext=tampered.ciphertext.slice(0,-5)+'AAAAA';
  await assert.rejects(importIdentity(JSON.stringify(tampered),passphrase),/could not be unlocked/);
  tampered.iterations=1;await assert.rejects(importIdentity(JSON.stringify(tampered),passphrase),/could not be unlocked/);
  await assert.rejects(exportIdentity(identity,'weak'),/at least 16/);
});
test('browser never accepts an insecure remote, credential-bearing, or path-bearing host',()=>{
  for(const host of ['http://example.org','https://user:pass@example.org','https://example.org/path','https://example.org/','javascript:alert(1)'])assert.throws(()=>validateHost(host));
  assert.equal(validateHost('https://example.org'),'https://example.org');assert.equal(validateHost('http://127.0.0.1:3015'),'http://127.0.0.1:3015');
});
test('browser reconstructs authorship and community authority from signatures; private report evidence is withheld',async()=>{
  const owner=await createIdentity(),visitor=await createIdentity(),host='https://verified.example';
  let state=applyEvent(null,await signCommand(owner,null,'network.create',{name:'Verified community',visibility:'public',host,enrollment:'open'}));
  const old=publicView(state);
  state=applyEvent(state,await signCommand(owner,state,'post.create',{text:'Signed genuine content',parentId:null}));
  const postId=Object.keys(state.posts)[0];
  state=applyEvent(state,await signCommand(visitor,state,'report.create',{postId,reviewedText:'Signed genuine content',reason:'Sensitive reporter reason',shareWithModerators:true}));
  const projected=publicView(state);assert.equal(JSON.stringify(projected).includes('Sensitive reporter reason'),false);assert.equal(projected.proofs.some(value=>value.includes('~')),false);
  const forged={...projected,owner:visitor.actorId,members:[{actorId:visitor.actorId,role:'owner'}],posts:[{text:'Forged content',actorId:owner.actorId}]};
  const verified=await verifyNetworkView(forged,host);assert.equal(verified.owner,owner.actorId);assert.equal(verified.posts[0].text,'Signed genuine content');assert.equal(verified.members[0].actorId,owner.actorId);
  await assert.rejects(verifyNetworkView(old,host),/older or conflicting/);
  const modified=structuredClone(projected);modified.proofs[1]=modified.proofs[1].slice(0,-5)+'AAAAA';
  await assert.rejects(verifyNetworkView(modified,host),/signature/);
  const stripped=structuredClone(projected);stripped.proofs.splice(1,1);await assert.rejects(verifyNetworkView(stripped,host),/revision_conflict/);
});

test('a longer signed fork cannot replace a previously verified history prefix',async()=>{
  const owner=await createIdentity(),host='https://fork-proof.example';
  const genesis=applyEvent(null,await signCommand(owner,null,'network.create',{name:'Pinned history',visibility:'public',host}));
  const accepted=applyEvent(genesis,await signCommand(owner,genesis,'post.create',{text:'Already verified',parentId:null}));
  await verifyNetworkView(publicView(accepted),host);
  let fork=applyEvent(genesis,await signCommand(owner,genesis,'post.create',{text:'Conflicting branch',parentId:null}));
  fork=applyEvent(fork,await signCommand(owner,fork,'post.create',{text:'Longer branch',parentId:null}));
  await assert.rejects(verifyNetworkView(publicView(fork),host),/older or conflicting/);
  const continuation=applyEvent(accepted,await signCommand(owner,accepted,'post.create',{text:'Valid continuation',parentId:null}));
  assert.equal((await verifyNetworkView(publicView(continuation),host)).head,continuation.head);
});

test('a requested network cannot be substituted and a rejected write cannot advance its checkpoint',async()=>{
  const owner=await createIdentity(),host='https://response-proof.example';
  const genesis=applyEvent(null,await signCommand(owner,null,'network.create',{name:'Requested',visibility:'public',host}));
  const other=applyEvent(null,await signCommand(owner,null,'network.create',{name:'Substituted',visibility:'public',host}));
  const originalFetch=globalThis.fetch;
  try{
    globalThis.fetch=async()=>Response.json(publicView(other));
    await assert.rejects(readNetwork(host,genesis.id),/did not match/);
    let unrelated=applyEvent(genesis,await signCommand(owner,genesis,'post.create',{text:'Unrelated request',parentId:null}));
    const accepted=unrelated;
    unrelated=applyEvent(unrelated,await signCommand(owner,unrelated,'post.create',{text:'Unrequested continuation',parentId:null}));
    globalThis.fetch=async()=>Response.json(publicView(unrelated));
    await assert.rejects(writeNetwork(host,owner,publicView(genesis),'post.create',{text:'My actual request',parentId:null}),/did not match/);
    assert.equal((await verifyNetworkView(publicView(accepted),host)).head,accepted.head);
  }finally{globalThis.fetch=originalFetch;}
});

test('archive signatures are verified locally before signing or uploading a move',async()=>{
  const owner=await createIdentity(),host='https://archive-source.example',destination='https://archive-target.example';
  let state=applyEvent(null,await signCommand(owner,null,'network.create',{name:'Verified archive',visibility:'public',host}));
  state=applyEvent(state,await signCommand(owner,state,'host.freeze',{destination}));
  const events=[...state.events];events[0]=events[0].slice(0,-5)+'AAAAA';
  const originalFetch=globalThis.fetch;let calls=0;
  try{globalThis.fetch=async()=>{calls++;throw new Error('must not upload');};
    await assert.rejects(importNetwork(destination,owner,JSON.stringify({protocol:'glance-owned-network/1',events})),/signature/);
    assert.equal(calls,0);
  }finally{globalThis.fetch=originalFetch;}
});

test('browser private-report verification rejects coerced and noncanonical nonces',async()=>{
  const owner=await createIdentity(),host='https://report-nonce.example',encode=value=>Buffer.from(JSON.stringify(value)).toString('base64url');
  let state=applyEvent(null,await signCommand(owner,null,'network.create',{name:'Private report evidence',visibility:'public',host}));
  state=applyEvent(state,await signCommand(owner,state,'post.create',{text:'Reviewed snapshot',parentId:null}));
  const originalFetch=globalThis.fetch;
  try{for(const nonce of [['A'.repeat(43)],'A'.repeat(42)+'B']){
    const body=Buffer.from(JSON.stringify({nonce,data:{postId:Object.keys(state.posts)[0],reviewedText:'Reviewed snapshot',reason:'Reason',shareWithModerators:true}}));
    const event={protocol:'glance-owned-network/1',networkId:state.id,eventId:crypto.randomUUID(),sequence:state.sequence+1,previousHash:state.head,issuedAt:new Date().toISOString(),actorId:owner.actorId,action:'report.create',data:{sha256:Buffer.from(await crypto.subtle.digest('SHA-256',body)).toString('base64url')}};
    const input=`${encode({alg:'EdDSA',typ:event.protocol,jwk:owner.publicJwk})}.${encode(event)}`;
    const jws=`${input}.${Buffer.from(await crypto.subtle.sign('Ed25519',owner.privateKey,Buffer.from(input))).toString('base64url')}`;
    globalThis.fetch=async()=>Response.json({...publicView(state),sequence:event.sequence,head:Buffer.from(await crypto.subtle.digest('SHA-256',Buffer.from(jws))).toString('base64url'),proofs:[...state.events,`${jws}~${body.toString('base64url')}`]});
    await assert.rejects(readReports(host,owner,publicView(state)),/Invalid report evidence|Invalid encoded value/);
  }}finally{globalThis.fetch=originalFetch;}
});

test('browser rejects base64 aliases of signed proofs, actor keys, and private sidecars',async()=>{
  const owner=await createIdentity(),host='https://canonical-proof.example';
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const alias=value=>value.slice(0,-1)+alphabet[alphabet.indexOf(value.at(-1))+1];
  await assert.rejects(actorId({...owner.publicJwk,x:alias(owner.publicJwk.x)}),/Invalid encoded value/);
  let state=applyEvent(null,await signCommand(owner,null,'network.create',{name:'Canonical proof',visibility:'public',host}));
  const projection=publicView(state),parts=projection.proofs[0].split('.');
  parts[2]=alias(parts[2]);
  assert.deepEqual(Buffer.from(parts[2],'base64url'),Buffer.from(projection.proofs[0].split('.')[2],'base64url'));
  await assert.rejects(verifyNetworkView({...projection,proofs:[parts.join('.')]},host),/Invalid encoded value/);
  state=applyEvent(state,await signCommand(owner,state,'post.create',{text:'Reviewed post',parentId:null}));
  state=applyEvent(state,await signCommand(owner,state,'report.create',{postId:Object.keys(state.posts)[0],reviewedText:'Reviewed post',reason:'Reason',shareWithModerators:true}));
  const originalFetch=globalThis.fetch;
  try{
    globalThis.fetch=async()=>Response.json({...publicView(state),proofs:[...state.events.slice(0,-1),state.events.at(-1)+'!']});
    await assert.rejects(readReports(host,owner,publicView(state)),/Invalid encoded value/);
    globalThis.fetch=async()=>Response.json({...publicView(state),proofs:state.events});
    assert.equal((await readReports(host,owner,publicView(state)))[0].reason,'Reason');
  }finally{globalThis.fetch=originalFetch;}
});

test('feed pages derive chronology from signed history and reject omitted, reordered, or revision-drifted hints',async()=>{
  const owner=await createIdentity(),host='https://feed-proof.example';let state=applyEvent(null,await signCommand(owner,null,'network.create',{name:'Paginated public history',visibility:'public',host}));
  for(let index=0;index<23;index++)state=applyEvent(state,await signCommand(owner,state,'post.create',{text:`Message ${index}`,parentId:null}));
  const originalFetch=globalThis.fetch,network=publicView(state),expected=pageNetworkFeed(network,'posts');
  const reply=()=>({network,page:{kind:'posts',ids:expected.items.map(item=>item.id),nextCursor:expected.nextCursor,sequence:network.sequence,head:network.head}});
  try{globalThis.fetch=async()=>Response.json(reply());const first=await readFeed(host,state.id);assert.equal(first.items.length,20);assert.equal(first.items[0].text,'Message 22');
    const remaining=pageNetworkFeed(network,'posts',{beforeSequence:expected.items.at(-1).createdSequence});
    globalThis.fetch=async()=>Response.json({network,page:{kind:'posts',ids:remaining.items.map(item=>item.id),nextCursor:null,sequence:network.sequence,head:network.head}});
    assert.equal((await readFeed(host,state.id,{cursor:first.nextCursor})).items.length,3);
    for(const ids of [expected.items.map(item=>item.id).slice(1),expected.items.map(item=>item.id).reverse()]){globalThis.fetch=async()=>Response.json({...reply(),page:{...reply().page,ids}});await assert.rejects(readFeed(host,state.id),/inconsistent page/);}
    state=applyEvent(state,await signCommand(owner,state,'post.create',{text:'New revision',parentId:null}));globalThis.fetch=async()=>Response.json({...reply(),network:publicView(state)});await assert.rejects(readFeed(host,state.id,{cursor:first.nextCursor}),/changed/);
  }finally{globalThis.fetch=originalFetch;}
});

test('uncertain writes reconcile by GET and exact replay receipts may refer to an earlier accepted proof',async()=>{
  const owner=await createIdentity(),host='https://receipt-proof.example';let state=applyEvent(null,await signCommand(owner,null,'network.create',{name:'Receipt proof',visibility:'public',host}));
  const operation=await prepareNetworkWrite(owner,publicView(state),'post.create',{text:'Exactly once',parentId:null});state=applyEvent(state,operation.event);state=applyEvent(state,await signCommand(owner,state,'post.create',{text:'Later accepted change',parentId:null}));
  const originalFetch=globalThis.fetch,calls=[];
  try{globalThis.fetch=async(_url,options)=>{calls.push(options);return Response.json({...publicView(state),receipt:{eventId:operation.eventId,sequence:operation.sequence,digest:operation.digest,replayed:true}});};
    const replayed=await submitNetworkWrite(host,operation);assert.equal(replayed.posts.length,2);assert.equal(JSON.parse(calls[0].body).event,operation.event);
    const reconciliation=await reconcileNetworkWrite(host,operation);assert.equal(reconciliation.accepted,true);assert.equal(calls[1].method,'GET');assert.equal(calls[1].body,undefined);
    globalThis.fetch=async()=>Response.json({...publicView(state),receipt:{eventId:crypto.randomUUID(),sequence:operation.sequence,digest:operation.digest,replayed:true}});await assert.rejects(submitNetworkWrite(host,operation),/did not match/);
  }finally{globalThis.fetch=originalFetch;}
});

test('a lost import response retries the same prepared resume proof after later writes',async()=>{
  const owner=await createIdentity(),host='https://import-source.example',target='https://import-target.example';let state=applyEvent(null,await signCommand(owner,null,'network.create',{name:'Resumable move',visibility:'public',host}));state=applyEvent(state,await signCommand(owner,state,'host.freeze',{destination:target}));
  const operation=await prepareNetworkImport(target,owner,JSON.stringify({protocol:'glance-owned-network/1',events:state.events}));const originalFetch=globalThis.fetch,bodies=[];let accepted=applyEvent(state,operation.event,{importing:true});
  try{globalThis.fetch=async(_url,options)=>{bodies.push(options.body);if(bodies.length===1)throw new Error('Synthetic lost response');accepted=applyEvent(accepted,await signCommand(owner,accepted,'post.create',{text:'After the move',parentId:null}));return Response.json({...publicView(accepted),receipt:{eventId:operation.eventId,sequence:operation.sequence,digest:operation.digest,replayed:true}});};
    await assert.rejects(submitNetworkWrite(target,operation),/lost response/);const resumed=await submitNetworkWrite(target,operation);assert.equal(bodies[0],bodies[1]);assert.equal(resumed.host,target);assert.equal(resumed.posts[0].text,'After the move');
  }finally{globalThis.fetch=originalFetch;}
});
