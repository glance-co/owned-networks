// SPDX-License-Identifier: Apache-2.0
import { actorId } from './index.mjs';

const databaseName='glance-network-profiles-v1',storeName='profiles';
const scopes=value=>value===null||value===undefined?'device':`account:${value}`;
async function database(){
  return new Promise((resolve,reject)=>{
    let request;try{request=indexedDB.open(databaseName,1);}catch{reject(new Error('This browser could not open network profile storage. Use a browser with device storage enabled.'));return;}
    let settled=false;const fail=message=>{if(settled)return;settled=true;clearTimeout(timer);reject(new Error(message));};
    const timer=setTimeout(()=>fail('Opening the saved network profile took too long. Nothing was replaced. Try again.'),8000);
    request.onupgradeneeded=()=>request.result.createObjectStore(storeName,{keyPath:'scope'});
    request.onsuccess=()=>{if(settled){request.result.close();return;}settled=true;clearTimeout(timer);resolve(request.result);};
    request.onerror=()=>fail('Your saved network profile could not be opened. Nothing was replaced.');
    request.onblocked=()=>fail('Close other Glance tabs, then try opening your network profile again.');
  });
}
async function validate(profile){
  const identity=profile?.identity;
  if(!identity||await actorId(identity.publicJwk)!==identity.actorId||identity.privateKey?.type!=='private'||identity.privateKey.algorithm.name!=='Ed25519'||typeof profile.displayName!=='string'||profile.displayName.length>80)throw new Error('Your saved network profile could not be verified. Restore its recovery file; do not replace it.');
  const publicKey=await crypto.subtle.importKey('jwk',identity.publicJwk,'Ed25519',false,['verify']),challenge=crypto.getRandomValues(new Uint8Array(32));
  if(!await crypto.subtle.verify('Ed25519',publicKey,await crypto.subtle.sign('Ed25519',identity.privateKey,challenge),challenge))throw new Error('The saved network profile does not match its signing key. Nothing was replaced.');
  return profile;
}
export async function readDeviceProfile(accountId=null){
  const db=await database();try{const value=await new Promise((resolve,reject)=>{const request=db.transaction(storeName).objectStore(storeName).get(scopes(accountId));request.onsuccess=()=>resolve(request.result??null);request.onerror=()=>reject(new Error('The saved network profile could not be read.'));});return value===null?null:await validate(value);}finally{db.close();}
}
export async function saveDeviceProfile(accountId,profile){
  await validate(profile);const db=await database();
  try{return await new Promise((resolve,reject)=>{
    const transaction=db.transaction(storeName,'readwrite'),store=transaction.objectStore(storeName),request=store.get(scopes(accountId));let refused=false,saved;
    request.onsuccess=()=>{const existing=request.result;if(existing&&existing.identity?.actorId!==profile.identity.actorId){refused=true;transaction.abort();return;}
      saved=existing?{...existing,recoveryReviewed:existing.recoveryReviewed||profile.recoveryReviewed}:{...profile,scope:scopes(accountId)};store.put(saved);};
    transaction.oncomplete=()=>resolve(saved);transaction.onerror=transaction.onabort=()=>reject(new Error(refused?'This recovery file belongs to a different network profile. The saved profile was not replaced.':'The network profile could not be saved on this device. Nothing was published.'));
  });}finally{db.close();}
}

/** Metadata updates preserve the signing key and other tabs' unrelated drafts. */
export async function updateDeviceProfile(accountId,expectedActor,changes){
  const db=await database();try{return await new Promise((resolve,reject)=>{
    const transaction=db.transaction(storeName,'readwrite'),store=transaction.objectStore(storeName),request=store.get(scopes(accountId));let updated;
    request.onsuccess=()=>{const saved=request.result;if(!saved||saved.identity?.actorId!==expectedActor){transaction.abort();return;}
      updated={...saved,...(changes.displayName!==undefined?{displayName:changes.displayName}:{}),...(changes.recoveryReviewed!==undefined?{recoveryReviewed:changes.recoveryReviewed}:{}),...(changes.pendingWrite!==undefined?{pendingWrite:changes.pendingWrite}:{}),
        readThrough:{...saved.readThrough,...changes.readThrough},drafts:{...saved.drafts,...changes.drafts}};store.put(updated);};
    transaction.oncomplete=()=>resolve(updated);transaction.onerror=transaction.onabort=()=>reject(new Error('Your network profile changed or could not be saved. Reload it before continuing.'));
  });}finally{db.close();}
}
