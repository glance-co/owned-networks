// SPDX-License-Identifier: Apache-2.0
// Browser-only key custody. No private key, passphrase, or backup is sent to a host.
import { applyVerifiedEvent, publicView } from '../../v3-network-protocol/src/state.mjs';
export { reportEvidence } from '../../v3-network-protocol/src/state.mjs';
export const protocol='glance-owned-network/1';
const utf8=new TextEncoder(), decode=new TextDecoder('utf-8',{fatal:true});
const b64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64=value=>{if(typeof value!=='string'||!/^[A-Za-z0-9_-]+$/.test(value))throw new Error('Invalid encoded value.');const decoded=Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),char=>char.charCodeAt(0));if(b64(decoded)!==value)throw new Error('Invalid encoded value.');return decoded;};
const json64=value=>b64(utf8.encode(JSON.stringify(value)));
const publicOnly=key=>({kty:'OKP',crv:'Ed25519',x:key.x});
export function validateHost(value){const url=new URL(value);if(url.origin!==value||url.username||url.password||!(url.protocol==='https:'||url.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(url.hostname)))throw new Error('Use an HTTPS host origin, without a path. Loopback HTTP is allowed for local tests.');return url.origin;}
export async function actorId(publicJwk){if(!publicJwk||publicJwk.kty!=='OKP'||publicJwk.crv!=='Ed25519'||typeof publicJwk.x!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(publicJwk.x)||'d' in publicJwk||unb64(publicJwk.x).length!==32)throw new Error('Invalid public identity.');return `urn:glance:actor:${b64(await crypto.subtle.digest('SHA-256',utf8.encode(JSON.stringify({crv:'Ed25519',kty:'OKP',x:publicJwk.x}))))}`;}
export async function createIdentity(){const pair=await crypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);const publicJwk=publicOnly(await crypto.subtle.exportKey('jwk',pair.publicKey));return {actorId:await actorId(publicJwk),publicJwk,privateKey:pair.privateKey};}
const backupFormat='glance-actor-backup/1',iterations=600_000;
async function backupKey(passphrase,salt){if(typeof passphrase!=='string'||passphrase.length<16||passphrase.length>1024)throw new Error('Use a backup passphrase of at least 16 characters.');const base=await crypto.subtle.importKey('raw',utf8.encode(passphrase),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}
export async function exportIdentity(identity,passphrase){const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));const key=await backupKey(passphrase,salt);const privateJwk=await crypto.subtle.exportKey('jwk',identity.privateKey);const content=utf8.encode(JSON.stringify({actorId:identity.actorId,publicJwk:identity.publicJwk,privateJwk}));try {const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:utf8.encode(backupFormat),tagLength:128},key,content);return JSON.stringify({format:backupFormat,kdf:'PBKDF2-SHA256',iterations,salt:b64(salt),iv:b64(iv),ciphertext:b64(ciphertext)},null,2);}finally{content.fill(0);}}
export async function importIdentity(backup,passphrase){if(typeof backup!=='string'||backup.length>16_000)throw new Error('Invalid backup.');let content;try{const value=JSON.parse(backup);if(value.format!==backupFormat||value.kdf!=='PBKDF2-SHA256'||value.iterations!==iterations)throw new Error();const salt=unb64(value.salt),iv=unb64(value.iv);if(salt.length!==16||iv.length!==12)throw new Error();content=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:utf8.encode(backupFormat),tagLength:128},await backupKey(passphrase,salt),unb64(value.ciphertext)));const parsed=JSON.parse(decode.decode(content)),id=await actorId(parsed.publicJwk);if(id!==parsed.actorId||parsed.privateJwk.x!==parsed.publicJwk.x||parsed.privateJwk.kty!=='OKP'||parsed.privateJwk.crv!=='Ed25519')throw new Error();const privateKey=await crypto.subtle.importKey('jwk',parsed.privateJwk,'Ed25519',true,['sign']);const publicKey=await crypto.subtle.importKey('jwk',parsed.publicJwk,'Ed25519',false,['verify']);const challenge=crypto.getRandomValues(new Uint8Array(32));if(!await crypto.subtle.verify('Ed25519',publicKey,await crypto.subtle.sign('Ed25519',privateKey,challenge),challenge))throw new Error();return {actorId:id,publicJwk:publicOnly(parsed.publicJwk),privateKey};}catch{throw new Error('Backup could not be unlocked. Check the file and passphrase.');}finally{content?.fill(0);}}
export async function signCommand(identity,state,action,data){const event={protocol,networkId:state?.id??crypto.randomUUID(),eventId:crypto.randomUUID(),sequence:(state?.sequence??0)+1,previousHash:state?.head??null,issuedAt:new Date().toISOString(),actorId:identity.actorId,action,data};const sidecar=['report.create','report.review'].includes(action)?json64({nonce:b64(crypto.getRandomValues(new Uint8Array(32))),data}):null;const signed=sidecar?{...event,data:{sha256:b64(await crypto.subtle.digest('SHA-256',unb64(sidecar)))}}:event;const input=`${json64({alg:'EdDSA',typ:protocol,jwk:identity.publicJwk})}.${json64(signed)}`;return `${input}.${b64(await crypto.subtle.sign('Ed25519',identity.privateKey,utf8.encode(input)))}${sidecar?'~'+sidecar:''}`;}
export async function signRead(identity,id,purpose){return signCommand(identity,{id,sequence:0,head:null},purpose,{});}
const checkpoints=new Map();
async function verifyState(value,host,includePrivate=false,expectedId,expectedHead){
  if(!value||value.protocol!==protocol||!Array.isArray(value.proofs)||value.proofs.length<1||value.proofs.length>20_000)throw new Error('Network has no verifiable signed history.');
  if(expectedId&&value.id!==expectedId||expectedHead&&value.head!==expectedHead)throw new Error('Network response did not match the signed request.');
  let state=null;
  for(const compact of value.proofs){
    if(typeof compact!=='string'||compact.length>65_536||!includePrivate&&compact.includes('~'))throw new Error('Invalid public proof.');
    const [jws,sidecar,...extra]=compact.split('~');if(extra.length)throw new Error('Invalid proof.');
    const parts=jws.split('.');if(parts.length!==3)throw new Error('Invalid public proof.');
    const header=JSON.parse(decode.decode(unb64(parts[0]))),event=JSON.parse(decode.decode(unb64(parts[1])));
    if(header.alg!=='EdDSA'||header.typ!==protocol||Object.keys(header).sort().join(',')!=='alg,jwk,typ'||event.protocol!==protocol||Object.keys(event).sort().join(',')!=='action,actorId,data,eventId,issuedAt,networkId,previousHash,protocol,sequence'||!Number.isFinite(Date.parse(event.issuedAt))||!Number.isSafeInteger(event.sequence)||event.sequence<1||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(event.networkId)||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(event.eventId))throw new Error('Invalid public proof.');
    const signerId=await actorId(header.jwk);if(signerId!==event.actorId)throw new Error('Invalid signed actor.');
    const key=await crypto.subtle.importKey('jwk',header.jwk,'Ed25519',false,['verify']);
    if(!await crypto.subtle.verify('Ed25519',key,unb64(parts[2]),utf8.encode(`${parts[0]}.${parts[1]}`)))throw new Error('Invalid network signature.');
    const sensitive=['report.create','report.review'].includes(event.action);
    if(sensitive&&(!event.data||Object.keys(event.data).join(',')!=='sha256'||!/^[A-Za-z0-9_-]{43}$/.test(event.data.sha256)))throw new Error('Invalid report commitment.');
    if(sensitive&&sidecar){const body=unb64(sidecar);if(b64(await crypto.subtle.digest('SHA-256',body))!==event.data.sha256)throw new Error('Invalid private report evidence.');const privateData=JSON.parse(decode.decode(body));if(!privateData||Object.keys(privateData).sort().join(',')!=='data,nonce'||typeof privateData.nonce!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(privateData.nonce)||unb64(privateData.nonce).length!==32||b64(unb64(privateData.nonce))!==privateData.nonce)throw new Error('Invalid report evidence.');event.data=privateData.data;}else if(sidecar)throw new Error('Unexpected private data.');
    let dataActor=null;if(['member.add','delegation.grant'].includes(event.action))dataActor=await actorId(event.data.publicKey);
    state=applyVerifiedEvent(state,compact,{event,key:header.jwk,digest:b64(await crypto.subtle.digest('SHA-256',utf8.encode(jws))),privateDataMissing:sensitive&&!sidecar},{importing:true,inPlace:true,publicOnly:!includePrivate,actorIdForKey:()=>dataActor});
  }
  const verified=publicView(state);
  if(verified.id!==value.id||host!==null&&verified.host!==host||verified.head!==value.head||verified.sequence!==value.sequence)throw new Error('Network response does not match signed history.');
  // Derive authority, text, identity and delegation from the verified journal;
  // do not trust the server's unsigned projection for any of these fields.
  const checkpoint=checkpoints.get(state.id);
  if(checkpoint){
    const prior=value.proofs[checkpoint.sequence-1];
    if(state.sequence<checkpoint.sequence||!prior||b64(await crypto.subtle.digest('SHA-256',utf8.encode(prior.split('~')[0])))!==checkpoint.head)throw new Error('Host returned an older or conflicting signed history.');
  }
  checkpoints.set(state.id,{sequence:state.sequence,head:state.head});
  return state;
}
export async function verifyNetworkView(value,host){return publicView(await verifyState(value,host));}
export async function readReports(host,identity,network,signal){const response=await hostRequest(host,`/v1/networks/${network.id}/reports`,{token:await signRead(identity,network.id,'report.read'),signal});const verified=await verifyState(response,host,true,network.id);return Object.values(verified.reports);}

const errorText={source_freeze_unconfirmed:'The source has not confirmed this exact move. Keep the source online and verify its frozen archive before trying again.',source_verification_unavailable:'The destination could not verify the frozen source. Keep the source online through the first accepted import; use a supported HTTPS source.',service_busy:'This host is busy. Retry the same saved request shortly.',host_capacity:'This host has reached its network limit. Existing networks remain available; choose another service for a new network.',capacity:'This network reached a safety limit. Existing history can still be exported; ask its owner about next steps.',authority_denied:'This identity does not have permission. Ask a community owner to approve your public identity.',revision_conflict:'The network changed. Reload it before submitting again.',network_frozen:'This host is frozen for a move. Open the destination host.',private_e2ee_not_accepted:'Private encrypted networks are not available until security acceptance is complete.',rate_limited:'This host is receiving too many requests. Try again shortly.',stale_event:'This request expired. Reload before trying again.'};
export async function hostRequest(host,path,{payload,token,signal}={}) {
  validateHost(host); const controller=new AbortController(),abort=()=>controller.abort();if(signal?.aborted)throw new Error('Request cancelled.');signal?.addEventListener('abort',abort,{once:true});const timer=setTimeout(abort,15000);
  try { const response=await fetch(host+path,{method:payload?'POST':'GET',credentials:'omit',cache:'no-store',redirect:'error',signal:controller.signal,headers:{...(payload?{'Content-Type':'application/json'}:{}),...(token?{Authorization:'Bearer '+token}:{})},...(payload?{body:JSON.stringify(payload)}:{})});
    if(!response.headers.get('content-type')?.toLowerCase().includes('application/json'))throw new Error('Invalid network response.');
    const reader=response.body?.getReader();if(!reader)throw new Error('Missing network response.');const chunks=[];let size=0;while(true){const result=await reader.read();if(result.done)break;size+=result.value.length;if(size>4000000){await reader.cancel();throw new Error('Network response too large.');}chunks.push(result.value);}const all=new Uint8Array(size);let offset=0;for(const chunk of chunks){all.set(chunk,offset);offset+=chunk.length;}const data=JSON.parse(decode.decode(all));if(!response.ok)throw new Error(errorText[data?.error]??'The network host could not confirm this request. Reload before retrying.');return data;
  } finally {clearTimeout(timer);signal?.removeEventListener('abort',abort);}
}
export async function readNetwork(host,id,signal){if(!/^[a-f0-9-]{36}$/.test(id))throw new Error('Enter a valid network ID.');return publicView(await verifyState(await hostRequest(host,`/v1/networks/${id}`,{signal}),host,false,id));}
export async function prepareNetworkWrite(identity,state,action,data){
  const event=await signCommand(identity,state,action,data),body=JSON.parse(decode.decode(unb64(event.split('.')[1])));
  return Object.freeze({event,creating:state===null,networkId:body.networkId,eventId:body.eventId,sequence:body.sequence,digest:b64(await crypto.subtle.digest('SHA-256',utf8.encode(event.split('~')[0])))});
}
async function containsWrite(value,operation){
  const proof=value?.proofs?.[operation.sequence-1];
  return typeof proof==='string'&&b64(await crypto.subtle.digest('SHA-256',utf8.encode(proof.split('~')[0])))===operation.digest;
}
export async function submitNetworkWrite(host,operation,signal){
  const result=await hostRequest(host,operation.archive?'/v1/import':operation.creating?'/v1/networks':`/v1/networks/${operation.networkId}/events`,{payload:operation.archive?{protocol:operation.archive.protocol,events:operation.archive.events,resume:operation.event}:{event:operation.event},signal});
  const receipt=result?.receipt;
  if(!receipt||receipt.eventId!==operation.eventId||receipt.sequence!==operation.sequence||receipt.digest!==operation.digest||typeof receipt.replayed!=='boolean'||!await containsWrite(result,operation))throw new Error('Network response did not match the signed request. Reload saved state before retrying.');
  return publicView(await verifyState(result,host,false,operation.networkId));
}
export async function reconcileNetworkWrite(host,operation,signal){
  const raw=await hostRequest(host,`/v1/networks/${operation.networkId}`,{signal});
  const network=publicView(await verifyState(raw,host,false,operation.networkId));
  return {network,accepted:await containsWrite(raw,operation)};
}
export async function writeNetwork(host,identity,state,action,data,signal){return submitNetworkWrite(host,await prepareNetworkWrite(identity,state,action,data),signal);}

const feedProperties={posts:'posts',resources:'resources',events:'calendarEvents',polls:'polls'};
const exactKeys=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
function pageLimit(value){if(!Number.isSafeInteger(value)||value<1||value>20)throw new Error('Invalid page size.');return value;}
function parseCursor(cursor,keys){
  if(typeof cursor!=='string'||cursor.length>1000)throw new Error('Invalid page cursor.');
  try{const value=JSON.parse(decode.decode(unb64(cursor)));if(!exactKeys(value,keys)||value.version!==1)throw new Error();return value;}catch{throw new Error('Invalid page cursor.');}
}
export function networkFeed(network,kind){
  if(!Object.hasOwn(feedProperties,kind))throw new Error('Invalid network feed.');
  const items=network[feedProperties[kind]];
  if(!Array.isArray(items))throw new Error('This host does not yet support this network feed.');
  return [...items].sort((a,b)=>b.createdSequence-a.createdSequence);
}
export function pageNetworkFeed(network,kind,{limit=20,beforeSequence=null}={}){
  pageLimit(limit);const remaining=networkFeed(network,kind).filter(item=>beforeSequence===null||item.createdSequence<beforeSequence),items=remaining.slice(0,limit);
  return {items,nextCursor:remaining.length>limit?json64({version:1,networkId:network.id,kind,sequence:network.sequence,head:network.head,beforeSequence:items.at(-1).createdSequence}):null};
}
export async function readFeed(host,id,{kind='posts',cursor=null,limit=20}={},signal){
  pageLimit(limit);if(!Object.hasOwn(feedProperties,kind)||!/^[a-f0-9-]{36}$/.test(id))throw new Error('Invalid network feed.');
  const after=cursor===null?null:parseCursor(cursor,['version','networkId','kind','sequence','head','beforeSequence']);
  if(after&&(after.networkId!==id||after.kind!==kind||!Number.isSafeInteger(after.sequence)||!Number.isSafeInteger(after.beforeSequence)||after.beforeSequence<1||after.beforeSequence>after.sequence||typeof after.head!=='string'))throw new Error('Invalid page cursor.');
  const params=new URLSearchParams({kind,limit:String(limit),...(cursor?{cursor}:{})});
  const raw=await hostRequest(host,`/v1/networks/${id}/feed?${params}`,{signal});
  // Page order and contents come from verified history, never unsigned hints.
  const network=publicView(await verifyState(raw?.network,host,false,id));
  if(after&&(after.sequence!==network.sequence||after.head!==network.head))throw new Error('The network changed. Reload from the first page.');
  const {items,nextCursor}=pageNetworkFeed(network,kind,{limit,beforeSequence:after?.beforeSequence??null});
  const page=raw.page;
  if(!page||page.kind!==kind||page.sequence!==network.sequence||page.head!==network.head||JSON.stringify(page.ids)!==JSON.stringify(items.map(item=>item.id))||page.nextCursor!==nextCursor)throw new Error('The network host returned an inconsistent page.');
  return {network,items,nextCursor};
}
export async function discoverNetworks(host,{cursor=null,limit=20}={},signal){
  pageLimit(limit);const after=cursor===null?null:parseCursor(cursor,['version','afterId']);
  if(after&&!/^[a-f0-9-]{36}$/.test(after.afterId))throw new Error('Invalid page cursor.');
  const params=new URLSearchParams({limit:String(limit),...(cursor?{cursor}:{})});
  const raw=await hostRequest(host,`/v1/networks?${params}`,{signal});
  if(!raw||!Array.isArray(raw.networks)||raw.networks.length>limit||!(raw.nextCursor===null||typeof raw.nextCursor==='string'))throw new Error('Invalid network directory.');
  const networks=[];let previous=after?.afterId??'';
  for(const value of raw.networks){const network=await verifyNetworkView(value,host);if(network.id<=previous)throw new Error('Invalid network directory order.');previous=network.id;networks.push(network);}
  // Hosts may stop a page early to keep full signed histories within the byte budget.
  if(raw.nextCursor!==null&&(!networks.length||raw.nextCursor!==json64({version:1,afterId:previous})))throw new Error('Invalid network directory cursor.');
  return {networks,nextCursor:raw.nextCursor};
}
export async function prepareNetworkImport(host,identity,archiveText){validateHost(host);if(typeof archiveText!=='string'||archiveText.length>4_000_000)throw new Error('Archive is too large.');const archive=JSON.parse(archiveText);if(archive.protocol!==protocol||!Array.isArray(archive.events)||!archive.events.length||archive.events.length>20_000)throw new Error('Invalid network archive.');const last=archive.events.at(-1);if(typeof last!=='string'||last.length>65_536)throw new Error('Invalid network archive.');const event=JSON.parse(decode.decode(unb64(last.split('.')[1])));const head=b64(await crypto.subtle.digest('SHA-256',utf8.encode(last.split('~')[0])));const state=await verifyState({protocol,proofs:archive.events,id:event.networkId,sequence:event.sequence,head},null,true);if(!state.frozen||state.destination!==host||state.owner!==identity.actorId)throw new Error('This archive is not a frozen move to this host by your identity.');const operation=await prepareNetworkWrite(identity,state,'host.resume',{host});return Object.freeze({...operation,archive:Object.freeze({protocol,events:Object.freeze([...archive.events])})});}
export async function importNetwork(host,identity,archiveText,signal){return submitNetworkWrite(host,await prepareNetworkImport(host,identity,archiveText),signal);}
