// SPDX-License-Identifier: Apache-2.0
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from 'node:crypto';

import { PROTOCOL, ProtocolError, applyVerifiedEvent, publicView } from './state.mjs';
export { PROTOCOL, ProtocolError, publicView };
export { reportEvidence } from './state.mjs';
const fail = code => { throw new ProtocolError(code); };
const hash = value => createHash('sha256').update(value).digest('base64url');
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const strictUtf8=new TextDecoder('utf-8',{fatal:true});
const text = (value, maximum) => typeof value === 'string' && value.trim().length > 0 && value.length <= maximum && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => keys.includes(key)) && keys.every(key => Object.hasOwn(value, key));
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);

export function publicKey(jwk) {
  if (!exact(jwk, ['kty', 'crv', 'x']) || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x)) fail('invalid_public_key');
  if(Buffer.from(jwk.x,'base64url').length!==32||Buffer.from(jwk.x,'base64url').toString('base64url')!==jwk.x)fail('invalid_public_key');
  try { createPublicKey({ key: jwk, format: 'jwk' }); } catch { fail('invalid_public_key'); }
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
}
// RFC 7638 JWK thumbprint, independent of email address and hosting endpoint.
export function actorId(jwk) { const key = publicKey(jwk); return `urn:glance:actor:${hash(JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x }))}`; }
export function createIdentity() {
  const pair = generateKeyPairSync('ed25519');
  const publicJwk = publicKey(pair.publicKey.export({ format: 'jwk' }));
  return { actorId: actorId(publicJwk), publicJwk, privateJwk: pair.privateKey.export({ format: 'jwk' }) };
}
// RFC 7515 compact JWS + RFC 8037 EdDSA. This is authentication, not encryption.
export function signEvent(identity, event) {
  const sidecar = ['report.create','report.review'].includes(event.action) ? encode({nonce:randomBytes(32).toString('base64url'),data:event.data}) : null;
  const signed = sidecar ? { ...event, data: { sha256: hash(Buffer.from(sidecar,'base64url')) } } : event;
  const protectedHeader = encode({ alg: 'EdDSA', typ: PROTOCOL, jwk: publicKey(identity.publicJwk) });
  const input = `${protectedHeader}.${encode(signed)}`;
  return `${input}.${sign(null, Buffer.from(input), createPrivateKey({ key: identity.privateJwk, format: 'jwk' })).toString('base64url')}${sidecar ? `~${sidecar}` : ''}`;
}
export function decodeEvent(compact) {
  if (typeof compact !== 'string' || compact.length > 65_536) fail('invalid_signature');
  const [jws,sidecar,...extra] = compact.split('~');
  if(extra.length) fail('invalid_signature');
  const parts = jws.split('.');
  const canonical = part => typeof part === 'string' && /^[A-Za-z0-9_-]+$/.test(part) && Buffer.from(part,'base64url').toString('base64url') === part;
  if (parts.length !== 3 || parts.some(part => !canonical(part)) || sidecar !== undefined && !canonical(sidecar)) fail('invalid_signature');
  try {
    const header = JSON.parse(strictUtf8.decode(Buffer.from(parts[0], 'base64url')));
    if (!exact(header, ['alg', 'typ', 'jwk']) || header.alg !== 'EdDSA' || header.typ !== PROTOCOL) fail('invalid_signature');
    const key = publicKey(header.jwk);
    if (!verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey({ key, format: 'jwk' }), Buffer.from(parts[2], 'base64url'))) fail('invalid_signature');
    const event = JSON.parse(strictUtf8.decode(Buffer.from(parts[1], 'base64url')));
    if (!exact(event, ['protocol','networkId','eventId','sequence','previousHash','issuedAt','actorId','action','data']) || event.protocol !== PROTOCOL || !uuid(event.networkId) || !uuid(event.eventId) || !Number.isSafeInteger(event.sequence) || event.sequence < 1 || !Number.isFinite(Date.parse(event.issuedAt)) || event.actorId !== actorId(key)) fail('invalid_event');
    const sensitive = ['report.create','report.review'].includes(event.action);
    if (sensitive) {
      if (!exact(event.data,['sha256']) || typeof event.data.sha256 !== 'string') fail('invalid_report_commitment');
      if (sidecar) { const body = Buffer.from(sidecar,'base64url'); if (hash(body) !== event.data.sha256) fail('invalid_report_commitment'); const privateData=JSON.parse(strictUtf8.decode(body));if(!exact(privateData,['nonce','data'])||typeof privateData.nonce!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(privateData.nonce)||Buffer.from(privateData.nonce,'base64url').length!==32||Buffer.from(privateData.nonce,'base64url').toString('base64url')!==privateData.nonce)fail('invalid_report_commitment');event.data=privateData.data; }
    } else if(sidecar) fail('unexpected_private_data');
    return { event, key, digest: hash(jws), privateDataMissing:sensitive&&!sidecar };
  } catch (error) { if (error instanceof ProtocolError) throw error; fail('invalid_signature'); }
}
export function nextEvent(identity, state, action, data, now = new Date()) {
  return signEvent(identity, { protocol: PROTOCOL, networkId: state?.id ?? randomUUID(), eventId: randomUUID(), sequence: (state?.sequence ?? 0) + 1,
    previousHash: state?.head ?? null, issuedAt: now.toISOString(), actorId: identity.actorId, action, data });
}
export function applyEvent(previous, compact, options={}) { return applyVerifiedEvent(previous,compact,decodeEvent(compact),{...options,actorIdForKey:actorId}); }
export function replay(events,{publicOnly=false}={}) {
  if (!Array.isArray(events) || events.length < 1 || events.length > 20_000) fail('invalid_archive');
  return events.reduce((state, event) => applyEvent(state, event, { importing: true,publicOnly,inPlace:true }), null);
}
export function signRead(identity, networkId, purpose, now = new Date()) {
  return signEvent(identity, { protocol: PROTOCOL, networkId, eventId: randomUUID(), sequence: 1, previousHash: null, issuedAt: now.toISOString(), actorId: identity.actorId, action: purpose, data: {} });
}
export function authorizeRead(state, token, purpose, now = Date.now()) {
  const { event } = decodeEvent(token);
  if (event.networkId !== state.id || event.action !== purpose || Math.abs(now - Date.parse(event.issuedAt)) > 60_000) fail('authority_denied');
  if (purpose === 'archive.read' && event.actorId === state.owner) return;
  const member = state.members[event.actorId], delegate = state.delegates[event.actorId];
  if (purpose === 'report.read' && (member?.role === 'owner' || member?.role === 'administrator' || delegate?.scopes.includes('report.read') && Date.parse(delegate.expiresAt) > now)) return;
  fail('authority_denied');
}
