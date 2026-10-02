// SPDX-License-Identifier: Apache-2.0
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { PROTOCOL, ProtocolError, applyEvent, authorizeRead, decodeEvent, publicView, replay } from '../../v3-network-protocol/src/index.mjs';
import { createFileNetworkStore } from './file-store.mjs';
import { replayJournal } from './replay.mjs';
import { verifySourceFreeze as defaultSourceVerifier } from './source-proof.mjs';

const uuid=value=>typeof value==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
const fail=code=>{throw new ProtocolError(code);};
const reply=(response,status,value)=>{response.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});response.end(JSON.stringify(value));};
const cursorEncode=value=>Buffer.from(JSON.stringify(value)).toString('base64url');
function cursorDecode(value){try{if(typeof value!=='string'||value.length>1000||!/^[A-Za-z0-9_-]+$/.test(value)||Buffer.from(value,'base64url').toString('base64url')!==value)fail('invalid_cursor');return JSON.parse(Buffer.from(value,'base64url').toString('utf8'));}catch{fail('invalid_cursor');}}
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
function pageQuery(url,keys){if([...url.searchParams.keys()].some(key=>!keys.includes(key)||url.searchParams.getAll(key).length!==1))fail('invalid_request');const raw=url.searchParams.get('limit')??'20';if(!/^[1-9]\d?$/.test(raw)||Number(raw)>20)fail('invalid_request');return Number(raw);}
async function body(request,limit){
  let size=0,timedOut=false;const chunks=[];
  const timer=setTimeout(()=>{timedOut=true;request.destroy();},5000);timer.unref?.();
  try{
    for await(const chunk of request){size+=chunk.length;if(size>limit)fail('body_too_large');chunks.push(chunk);}
    try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{fail('invalid_json');}
  }catch(error){if(timedOut)fail('request_timeout');throw error;}finally{clearTimeout(timer);}
}
function validateOrigin(value){try{const url=new URL(value);if(url.origin!==value||url.username||url.password||!(url.protocol==='https:'||url.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(url.hostname)))throw new Error();return value;}catch{throw new Error('invalid_network_origin');}}

// Signed state is the portable acknowledgement. A receipt identifies the exact
// accepted proof inside it; no unsigned host assertion grants actor authority.
function acknowledged(state,compact,replayed=false){
  const {event,digest}=decodeEvent(compact),view={...publicView(state),receipt:{eventId:event.eventId,sequence:event.sequence,digest,replayed}};
  // Every acknowledgement must fit the client reader and a future full archive
  // import, including the maximum supported resume proof and JSON overhead.
  if(Buffer.byteLength(JSON.stringify(view))>3_900_000||Buffer.byteLength(JSON.stringify({protocol:PROTOCOL,events:state.events,resume:'x'.repeat(65_536)}))>4_000_000)fail('capacity');
  return view;
}
function accepted(previous,compact,event){
  if(!previous)return false;
  const index=previous.eventIds.indexOf(event.eventId);
  if(index<0)return false;
  if(previous.events[index]!==compact||index+1!==event.sequence)fail('revision_conflict');
  return true;
}

export async function createNetworkHandler({store,origin,webOrigins=[],now=()=>Date.now(),clientAddress=request=>request.socket.remoteAddress??'unknown',verifySourceFreeze=defaultSourceVerifier}) {
  validateOrigin(origin);webOrigins.forEach(validateOrigin);await store.health();
  const rate=async(subject,limit,windowMs)=>{const key=createHash('sha256').update(`${origin}\0${subject}`).digest('hex');if(!await store.takeRate(key,limit,windowMs))fail('rate_limited');};
  const fresh=event=>{if(Math.abs(now()-Date.parse(event.issuedAt))>60_000)fail('stale_event');};
  const handler=async(request,response)=>{
    try {
      const webOrigin=request.headers.origin;
      if(webOrigin){if(webOrigin!==origin&&!webOrigins.includes(webOrigin))return reply(response,403,{error:'origin_forbidden'});response.setHeader('Access-Control-Allow-Origin',webOrigin);response.setHeader('Vary','Origin');response.setHeader('Access-Control-Allow-Methods','GET, POST, OPTIONS');response.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');}
      if(request.method==='OPTIONS'){response.writeHead(204);response.end();return;}
      const url=new URL(request.url,origin);if(url.origin!==origin)fail('invalid_request');
      if(request.method==='GET'&&['/health','/v1/health'].includes(url.pathname)){if(url.search)fail('invalid_request');return reply(response,200,{ok:true,protocol:PROTOCOL,privateE2EE:false,federation:false,...await store.health()});}
      await rate(`address:${clientAddress(request)}`,240,60_000);
      if(request.method==='GET'&&url.pathname==='/v1/networks'){
        const limit=pageQuery(url,['limit','cursor']);let afterId='';
        if(url.searchParams.has('cursor')){const cursor=cursorDecode(url.searchParams.get('cursor'));if(!exact(cursor,['version','afterId'])||cursor.version!==1||!uuid(cursor.afterId))fail('invalid_cursor');afterId=cursor.afterId;}
        const listing=await store.list({afterId,limit:limit+1}),candidates=listing.items,networks=[];let bytes=0;
        for(const state of candidates.slice(0,limit)){const value=publicView(state),size=Buffer.byteLength(JSON.stringify(value));if(networks.length&&bytes+size>3_500_000)break;networks.push(value);bytes+=size;}
        const nextCursor=listing.hasMore||candidates.length>networks.length?cursorEncode({version:1,afterId:networks.at(-1).id}):null;
        return reply(response,200,{protocol:PROTOCOL,networks,nextCursor});
      }
      const match=/^\/v1\/networks\/([a-f0-9-]{36})(?:\/(events|archive|public-archive|handoff|reports|feed))?$/.exec(url.pathname);
      if(match&&!uuid(match[1]))fail('not_found');
      if(request.method==='GET'&&match){
        const state=await store.get(match[1]);if(!state)fail('not_found');
        if(match[2]==='feed'){
          const limit=pageQuery(url,['kind','limit','cursor']),kind=url.searchParams.get('kind')??'posts';
          if(!['posts','resources','events','polls'].includes(kind))fail('invalid_request');const collection={posts:'posts',resources:'resources',events:'calendarEvents',polls:'polls'}[kind];
          let beforeSequence=state.sequence+1;
          if(url.searchParams.has('cursor')){const cursor=cursorDecode(url.searchParams.get('cursor'));if(!exact(cursor,['version','networkId','kind','sequence','head','beforeSequence'])||cursor.version!==1||cursor.networkId!==state.id||cursor.kind!==kind||!Number.isSafeInteger(cursor.beforeSequence)||cursor.beforeSequence<1||cursor.beforeSequence>state.sequence+1)fail('invalid_cursor');if(cursor.sequence!==state.sequence||cursor.head!==state.head)fail('revision_conflict');beforeSequence=cursor.beforeSequence;}
          const candidates=Object.values(state[collection]).filter(item=>item.createdSequence<beforeSequence).sort((a,b)=>b.createdSequence-a.createdSequence);
          const selected=candidates.slice(0,limit),nextCursor=candidates.length>limit?cursorEncode({version:1,networkId:state.id,kind,sequence:state.sequence,head:state.head,beforeSequence:selected.at(-1).createdSequence}):null;
          return reply(response,200,{network:publicView(state),page:{kind,ids:selected.map(item=>item.id),nextCursor,sequence:state.sequence,head:state.head}});
        }
        if(url.search)fail('invalid_request');
        if(!match[2])return reply(response,200,publicView(state));
        if(match[2]==='public-archive')return reply(response,200,{protocol:PROTOCOL,scope:'public',events:publicView(state).proofs});
        if(match[2]==='handoff')return reply(response,200,{protocol:PROTOCOL,durableHandoff:store.durableHandoff,network:publicView(state)});
        if(!['archive','reports'].includes(match[2]))fail('not_found');
        const token=request.headers.authorization?.replace(/^Bearer /,'');authorizeRead(state,token,match[2]==='archive'?'archive.read':'report.read',now());
        return reply(response,200,match[2]==='archive'?{protocol:PROTOCOL,events:state.events}:{...publicView(state),proofs:state.events});
      }
      if(request.method!=='POST'){response.setHeader('Allow','GET, POST');return reply(response,405,{error:'method_not_allowed'});}
      if(url.search)fail('invalid_request');
      if(request.headers['content-type']?.split(';')[0]!=='application/json')return reply(response,415,{error:'json_required'});
      if(url.pathname==='/v1/import'){
        await rate(`import-address:${clientAddress(request)}`,5,60_000);await rate('import-global',30,60_000);
        const input=await body(request,4_000_000);if(!exact(input,['protocol','events','resume'])||input.protocol!==PROTOCOL)fail('unsupported_protocol');
        const {event}=decodeEvent(input.resume);
        await rate(`write:${event.actorId}`,60,60_000);
        const archived=await replayJournal(input.events);if(event.networkId!==archived.id)fail('invalid_handoff');
        const known=await store.get(archived.id);
        if(accepted(known,input.resume,event))return reply(response,200,acknowledged(known,input.resume,true));
        fresh(event);
        if(!archived.frozen||archived.destination!==origin)fail('invalid_handoff');
        if(known&&(!known.frozen||archived.sequence<=known.sequence||archived.events[known.sequence-1]!==known.events.at(-1)))fail('invalid_handoff');
        const proposed=applyEvent(archived,input.resume,{importing:true,admissionNow:now()});if(proposed.host!==origin||proposed.frozen)fail('invalid_handoff');
        // Never hold a database transaction/connection while contacting another
        // host. The source is frozen; destination authority is checked again
        // under its write lock after this bounded proof completes.
        await verifySourceFreeze(archived,origin);
        const result=await store.transaction(archived.id,async previous=>{
          if(accepted(previous,input.resume,event))return {result:acknowledged(previous,input.resume,true)};
          fresh(event);
          if(!archived.frozen||archived.destination!==origin)fail('invalid_handoff');
          // A returning network must extend this host's durable frozen prefix.
          if(previous&&(!previous.frozen||archived.sequence<=previous.sequence||archived.events[previous.sequence-1]!==previous.events.at(-1)))fail('invalid_handoff');
          const state=applyEvent(archived,input.resume,{importing:true,admissionNow:now()});if(state.host!==origin||state.frozen)fail('invalid_handoff');
          return {state,result:acknowledged(state,input.resume)};
        });return reply(response,result.receipt.replayed?200:201,result);
      }
      if(url.pathname!=='/v1/networks'&&(!match||match[2]!=='events'))fail('not_found');
      const input=await body(request,66_000);if(!exact(input,['event']))fail('invalid_request');
      const {event}=decodeEvent(input.event);if(match&&event.networkId!==match[1])fail('revision_conflict');
      await rate(`write:${event.actorId}`,60,60_000);
      if(url.pathname==='/v1/networks')await rate(`create:${event.actorId}`,10,3_600_000);
      const result=await store.transaction(event.networkId,async previous=>{
        if(accepted(previous,input.event,event))return {result:acknowledged(previous,input.event,true)};
        fresh(event);
        if(url.pathname==='/v1/networks'){
          if(previous)fail('revision_conflict');
          const state=applyEvent(null,input.event,{admissionNow:now()});if(state.host!==origin)fail('wrong_host');
          return {state,result:acknowledged(state,input.event)};
        }
        if(!previous)fail('not_found');if(previous.host!==origin)fail('wrong_host');
        const state=applyEvent(previous,input.event,{admissionNow:now()});return {state,result:acknowledged(state,input.event)};
      });return reply(response,200,result);
    }catch(error){
      const code=error instanceof ProtocolError?error.code:'service_unavailable';
      const status=['private_e2ee_not_accepted','service_unavailable','service_busy','host_capacity','capacity','source_verification_unavailable'].includes(code)?503:code==='rate_limited'?429:code==='authority_denied'?403:code==='not_found'?404:['revision_conflict','network_frozen','poll_closed','event_closed','event_cancelled','source_freeze_unconfirmed'].includes(code)?409:400;
      if(code==='rate_limited')response.setHeader('Retry-After','60');
      if(response.destroyed)return;if(!response.headersSent)reply(response,status,{error:code});else response.destroy();
    }
  };
  handler.close=()=>store.close();return handler;
}

export async function createNetworkServer({directory,store,...options}) {
  const ownedStore=store??await createFileNetworkStore({directory,origin:options.origin,now:options.now});
  let handler;try{handler=await createNetworkHandler({...options,store:ownedStore});}catch(error){await ownedStore.close();throw error;}
  const server=createServer({requestTimeout:5000,headersTimeout:5000,maxHeaderSize:8192},handler);
  const originalClose=server.close.bind(server);
  server.close=callback=>{originalClose(error=>{if(error){callback?.(error);return;}Promise.resolve(handler.close()).then(()=>callback?.(),failure=>callback?.(failure));});return server;};
  return server;
}
