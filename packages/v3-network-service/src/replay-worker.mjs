// SPDX-License-Identifier: Apache-2.0
import { parentPort } from 'node:worker_threads';
import { ProtocolError,replay } from '../../v3-network-protocol/src/index.mjs';
parentPort.on('message',({id,events,publicOnly})=>{
  try{parentPort.postMessage({id,state:replay(events,{publicOnly})});}
  catch(error){parentPort.postMessage({id,error:error instanceof ProtocolError?error.code:'service_unavailable'});}
});
