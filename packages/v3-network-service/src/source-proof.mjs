// SPDX-License-Identifier: Apache-2.0
import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { PROTOCOL,ProtocolError } from '../../v3-network-protocol/src/index.mjs';
import { replayJournal } from './replay.mjs';
const unavailable=()=>new ProtocolError('source_verification_unavailable');
export function isPublicAddress(value){try{const address=ipaddr.process(value);return isIP(value)!==0&&!value.includes('%')&&address.range()==='unicast'&&address.toString()!=='168.63.129.16';}catch{return false;}}
export async function resolvePublicSource(origin,{resolve=lookup}={}){
  let url;try{url=new URL(origin);if(url.origin!==origin||url.protocol!=='https:'||url.username||url.password)throw new Error();}catch{throw unavailable();}
  const hostname=url.hostname.replace(/^\[|\]$/g,'');
  let timer;
  try{
    const resolved=isIP(hostname)?[{address:hostname,family:isIP(hostname)}]:await Promise.race([resolve(hostname,{all:true,verbatim:true}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(unavailable()),3000);timer.unref?.();})]);
    if(!Array.isArray(resolved)||resolved.length<1||resolved.length>16||resolved.some(row=>![4,6].includes(row.family)||isIP(row.address)!==row.family||!isPublicAddress(row.address)))throw unavailable();
    return {url,hostname,address:resolved[0].address,family:resolved[0].family};
  }finally{clearTimeout(timer);}
}
export async function assertCommittedSource(archived,destination,value){
  if(!value||value.protocol!==PROTOCOL||value.durableHandoff!==true||value.network?.protocol!==PROTOCOL||!Array.isArray(value.network.proofs))throw unavailable();
  const state=await replayJournal(value.network.proofs,{publicOnly:true});
  if(state.id!==archived.id||state.host!==archived.host||state.sequence!==archived.sequence||state.head!==archived.head||!state.frozen||state.destination!==destination||value.network.id!==state.id||value.network.host!==state.host||value.network.sequence!==state.sequence||value.network.head!==state.head||value.network.frozen!==true||value.network.destination!==destination)throw new ProtocolError('source_freeze_unconfirmed');
}
export async function verifySourceFreeze(archived,destination,{resolve=lookup,requestHttps=request}={}){
  try{
    const pinned=await resolvePublicSource(archived.host,{resolve});
    const value=await new Promise((resolve,reject)=>{
      let done=false,timer;
      const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);if(error)reject(error);else resolve(value);};
      const outgoing=requestHttps({protocol:'https:',hostname:pinned.hostname,port:pinned.url.port||443,path:`/v1/networks/${archived.id}/handoff`,method:'GET',agent:false,autoSelectFamily:false,family:pinned.family,servername:isIP(pinned.hostname)?undefined:pinned.hostname,rejectUnauthorized:true,
        lookup:(_hostname,options,callback)=>options?.all?callback(null,[{address:pinned.address,family:pinned.family}]):callback(null,pinned.address,pinned.family),
        headers:{Accept:'application/json','User-Agent':'Glance-Owned-Network/1'}},response=>{
        if(response.statusCode!==200||!response.headers['content-type']?.toLowerCase().startsWith('application/json')||response.headers['content-encoding']&&response.headers['content-encoding']!=='identity'){response.destroy();finish(unavailable());return;}
        const chunks=[];let bytes=0;
        response.on('data',chunk=>{bytes+=chunk.length;if(bytes>4_000_000){response.destroy();outgoing.destroy();finish(unavailable());return;}chunks.push(chunk);});
        response.on('end',()=>{try{finish(null,JSON.parse(Buffer.concat(chunks).toString('utf8')));}catch{finish(unavailable());}});
        response.on('error',()=>finish(unavailable()));response.on('aborted',()=>finish(unavailable()));
      });
      timer=setTimeout(()=>{outgoing.destroy();finish(unavailable());},5000);timer.unref?.();
      outgoing.on('error',()=>finish(unavailable()));outgoing.end();
    });
    await assertCommittedSource(archived,destination,value);
  }catch(error){if(error instanceof ProtocolError)throw error;throw unavailable();}
}
