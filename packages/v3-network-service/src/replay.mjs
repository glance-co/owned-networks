// SPDX-License-Identifier: Apache-2.0
import { Worker } from 'node:worker_threads';
import { ProtocolError } from '../../v3-network-protocol/src/index.mjs';

// Keep untrusted historical signature verification off the API event loop.
// The pool is process-local admission only; it never caches network authority.
const slots=[],queue=[];let nextId=0;
function remove(slot){const index=slots.indexOf(slot);if(index>=0)slots.splice(index,1);}
function dispatch(){
  while(queue.length){
    if(queue[0].expiresAt<=Date.now()){const expired=queue.shift();clearTimeout(expired.timer);expired.reject(new ProtocolError('service_busy'));continue;}
    let slot=slots.find(value=>!value.job);
    if(!slot){if(slots.length>=2)return;const worker=new Worker(new URL('./replay-worker.mjs',import.meta.url),{resourceLimits:{maxOldGenerationSizeMb:96,maxYoungGenerationSizeMb:16}});slot={worker,job:null};slots.push(slot);worker.unref();
      const fail=()=>{const job=slot.job;slot.job=null;remove(slot);if(job){clearTimeout(job.timer);job.reject(new ProtocolError('service_unavailable'));}dispatch();};
      worker.on('error',fail);worker.on('exit',()=>{if(slots.includes(slot))fail();});
      worker.on('message',message=>{const job=slot.job;if(!job||message.id!==job.id)return;slot.job=null;clearTimeout(job.timer);worker.unref();if(message.error)job.reject(new ProtocolError(message.error));else job.resolve(message.state);dispatch();});
    }
    const job=queue.shift();slot.job=job;slot.worker.ref();
    slot.worker.postMessage({id:job.id,events:job.events,publicOnly:job.publicOnly});
  }
}
export function replayJournal(events,{publicOnly=false}={}){
  if(queue.length>=8)return Promise.reject(new ProtocolError('service_busy'));
  return new Promise((resolve,reject)=>{
    const job={id:++nextId,events,publicOnly,resolve,reject,timer:null,expiresAt:Date.now()+10000};
    job.timer=setTimeout(()=>{
      const index=queue.indexOf(job);if(index>=0)queue.splice(index,1);
      const slot=slots.find(value=>value.job===job);if(slot){slot.job=null;remove(slot);void slot.worker.terminate();}
      job.reject(new ProtocolError('service_busy'));dispatch();
    },10000);job.timer.unref?.();queue.push(job);dispatch();
  });
}
