// SPDX-License-Identifier: Apache-2.0
// Test injection only. The runtime verifier never permits loopback/private DNS.
import { ProtocolError,replay } from '../../v3-network-protocol/src/index.mjs';
export async function verifyLoopbackSourceForTests(archived,destination){
  const source=new URL(archived.host);if(source.protocol!=='http:'||source.hostname!=='127.0.0.1')throw new Error('synthetic_loopback_required');
  const response=await fetch(`${source.origin}/v1/networks/${archived.id}/handoff`,{redirect:'error',signal:AbortSignal.timeout(5000)});
  if(!response.ok)throw new ProtocolError('source_verification_unavailable');
  const value=await response.json(),state=replay(value.network.proofs,{publicOnly:true});
  if(state.id!==archived.id||state.host!==archived.host||state.sequence!==archived.sequence||state.head!==archived.head||!state.frozen||state.destination!==destination)throw new ProtocolError('source_freeze_unconfirmed');
}
