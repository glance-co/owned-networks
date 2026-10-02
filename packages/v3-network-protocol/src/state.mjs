// SPDX-License-Identifier: Apache-2.0
export const PROTOCOL = 'glance-owned-network/1';
export const JOURNAL_BUDGETS=Object.freeze({ordinary:1_200_000,control:1_440_000,handoff:1_500_000});
export class ProtocolError extends Error { constructor(code) { super(code); this.code=code; } }
const fail=code=>{throw new ProtocolError(code);};
const text=(value,maximum)=>typeof value==='string'&&value.trim().length>0&&value.length<=maximum&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(key=>keys.includes(key))&&keys.every(key=>Object.hasOwn(value,key));
const uuid=value=>typeof value==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
const actor=value=>typeof value==='string'&&/^urn:glance:actor:[A-Za-z0-9_-]{43}$/.test(value);
const optionalText=(value,maximum)=>value===''||text(value,maximum);
const timestamp=value=>typeof value==='string'&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;
const resourceUrl=value=>{try {const url=new URL(value);return typeof value==='string'&&value.length<=2000&&['https:','http:'].includes(url.protocol)&&!url.username&&!url.password&&!/[\u0000-\u0020\u007f]/.test(value);}catch{return false;}};
const publicKey=key=>{if(!exact(key,['kty','crv','x'])||key.kty!=='OKP'||key.crv!=='Ed25519'||typeof key.x!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(key.x)||'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.indexOf(key.x.at(-1))%4!==0)fail('invalid_public_key');return {kty:'OKP',crv:'Ed25519',x:key.x};};
function endpoint(value) {
  try { const url = new URL(value); return url.origin === value && (url.protocol === 'https:' || url.protocol === 'http:' && ['127.0.0.1','localhost','[::1]'].includes(url.hostname)); } catch { return false; }
}
export function reportEvidence(state,kind,id) {
  if(!['post','resource','event','poll'].includes(kind))fail('invalid_report');
  const collection={post:'posts',resource:'resources',event:'calendarEvents',poll:'polls'}[kind];
  const values=collection&&state[collection];
  const item=Array.isArray(values)?values.find(value=>value.id===id):values&&Object.hasOwn(values,id)?values[id]:null;
  if(!item)fail('invalid_report');
  if(kind==='post')return item.text;
  if(kind==='resource')return `${item.title}\n${item.url}\n${item.description}`;
  if(kind==='event')return `${item.title}\n${item.description}\nStarts: ${item.startsAt}\nEnds: ${item.endsAt}\nLocation: ${item.location}`;
  return `${item.question}\n${item.options.map((option,index)=>`${index+1}. ${option}`).join('\n')}\nCloses: ${item.closesAt}`;
}
export function applyVerifiedEvent(previous, compact, { event, key, digest, privateDataMissing }, { importing = false, publicOnly = false, actorIdForKey, admissionNow, inPlace = false } = {}) {
  const data = event.data;
  if (!previous) {
    const genesisKeys=['name','visibility','host',...(data?.enrollment!==undefined?['enrollment']:[]),...(data?.displayName!==undefined?['displayName']:[])];
    if (event.action !== 'network.create' || event.sequence !== 1 || event.previousHash !== null || !exact(data,genesisKeys) || data.enrollment !== undefined && !['open','approval'].includes(data.enrollment) || data.displayName!==undefined&&!text(data.displayName,80) || !text(data.name,100) || !endpoint(data.host)) fail('invalid_genesis');
    if (data.visibility !== 'public') fail('private_e2ee_not_accepted');
    return { id: event.networkId, name: data.name, visibility: 'public', enrollment: data.enrollment ?? 'approval', host: data.host, owner: event.actorId, sequence: 1, head: digest, frozen: false, createdAt:event.issuedAt,
      members: { [event.actorId]: { publicKey: key, role: 'owner', displayName:data.displayName?.trim()??null } }, pendingMembers:{},blockedActors: {}, delegates: {}, posts: {}, resources:{}, calendarEvents:{}, polls:{}, reports: {}, eventIds: [event.eventId], events: [compact],journalBytes:compact.length };
  }
  if (event.networkId !== previous.id || event.sequence !== previous.sequence + 1 || event.previousHash !== previous.head) fail('revision_conflict');
  if (previous.eventIds.includes(event.eventId)) fail('replayed_event');
  const journalBytes=(previous.journalBytes??previous.events.reduce((size,value)=>size+value.length,0))+compact.length;
  const handoff=['host.freeze','host.resume'].includes(event.action);
  const control=['post.delete','resource.delete','event.cancel','poll.close','member.remove','member.leave','member.role','member.reject','delegation.revoke','owner.transfer','report.review'].includes(event.action);
  if(journalBytes>(handoff?JOURNAL_BUDGETS.handoff:control?JOURNAL_BUDGETS.control:JOURNAL_BUDGETS.ordinary))fail('capacity');
  if (previous.frozen && !(importing && event.action === 'host.resume')) fail('network_frozen');
  // In-place replay is allowed only for a newly reconstructed, unexposed state;
  // discard that state entirely on failure. Live mutations retain copy-on-write.
  const state = inPlace?previous:structuredClone(previous), member = state.members[event.actorId], owner = event.actorId === state.owner;
  const admin = owner || member?.role === 'administrator';
  const delegate = state.delegates[event.actorId];
  // Event time is checked at admission; replay reconstructs authorization at its
  // historical event time without granting authority to expired delegates now.
  // A fresh command can be slightly in the future. It must be valid at both
  // admission and its signed time so every accepted journal remains replayable.
  const authorityTime=Math.max(admissionNow??Date.parse(event.issuedAt),Date.parse(event.issuedAt));
  const scoped = scope => delegate?.scopes.includes(scope) && Date.parse(delegate.expiresAt) > authorityTime;
  switch (event.action) {
    case 'member.join': {
      if (state.enrollment !== 'open' || member || state.blockedActors[event.actorId] || !(exact(data,[])||exact(data,['displayName'])&&text(data.displayName,80))) fail('authority_denied');
      if (Object.keys(state.members).length >= 1000) fail('capacity');
      state.members[event.actorId] = { publicKey: key, role: 'member', displayName:data.displayName?.trim()??null }; break;
    }
    case 'member.profile': {
      if(!member)fail('authority_denied');
      if(!exact(data,['displayName'])||!text(data.displayName,80))fail('invalid_profile');
      member.displayName=data.displayName.trim();break;
    }
    case 'member.request': {
      if(state.enrollment!=='approval'||member||state.blockedActors[event.actorId]||Object.hasOwn(state.pendingMembers,event.actorId))fail('authority_denied');
      if(!exact(data,['displayName'])||!text(data.displayName,80))fail('invalid_profile');
      if(Object.keys(state.pendingMembers).length>=1000)fail('capacity');
      state.pendingMembers[event.actorId]={actorId:event.actorId,publicKey:key,displayName:data.displayName.trim(),requestedAt:event.issuedAt};break;
    }
    case 'member.approve': {
      if(!owner)fail('authority_denied');
      if(!exact(data,['actorId','role'])||!actor(data.actorId)||!['member','administrator'].includes(data.role)||!Object.hasOwn(state.pendingMembers,data.actorId)||Object.hasOwn(state.members,data.actorId))fail('invalid_member');
      if(Object.keys(state.members).length>=1000)fail('capacity');
      const pending=state.pendingMembers[data.actorId];state.members[data.actorId]={publicKey:pending.publicKey,role:data.role,displayName:pending.displayName};delete state.pendingMembers[data.actorId];break;
    }
    case 'member.reject': {
      if(!owner||!exact(data,['actorId'])||!actor(data.actorId)||!Object.hasOwn(state.pendingMembers,data.actorId))fail('authority_denied');
      delete state.pendingMembers[data.actorId];break;
    }
    case 'member.role': {
      if(!owner||!exact(data,['actorId','role'])||!actor(data.actorId)||!Object.hasOwn(state.members,data.actorId)||data.actorId===state.owner||!['member','administrator'].includes(data.role))fail('authority_denied');
      state.members[data.actorId].role=data.role;break;
    }
    case 'member.add': {
      if (!owner) fail('authority_denied');
      if (!exact(data,['actorId','publicKey','role']) || !['member','administrator'].includes(data.role) || data.actorId !== actorIdForKey(data.publicKey) || data.actorId === state.owner) fail('invalid_member');
      if (Object.keys(state.members).length >= 1000 && !state.members[data.actorId]) fail('capacity');
      const displayName=state.members[data.actorId]?.displayName??null;
      delete state.blockedActors[data.actorId];delete state.pendingMembers[data.actorId];state.members[data.actorId] = { publicKey: publicKey(data.publicKey), role: data.role, displayName }; break;
    }
    case 'member.remove': {
      if (!owner || !exact(data,['actorId']) || !actor(data.actorId) || !Object.hasOwn(state.members,data.actorId) || data.actorId === state.owner) fail('authority_denied');
      delete state.members[data.actorId]; delete state.delegates[data.actorId]; state.blockedActors[data.actorId]=true; break;
    }
    case 'member.leave': {
      if (!member || owner || !exact(data,[])) fail('authority_denied');
      delete state.members[event.actorId]; delete state.delegates[event.actorId]; break;
    }
    case 'owner.transfer': {
      if (!owner || !exact(data,['actorId']) || !actor(data.actorId) || !Object.hasOwn(state.members,data.actorId) || data.actorId === state.owner) fail('authority_denied');
      state.members[state.owner].role = 'administrator'; state.owner = data.actorId; state.members[state.owner].role = 'owner'; break;
    }
    case 'delegation.grant': {
      if (!owner) fail('authority_denied');
      if (!exact(data,['actorId','publicKey','scopes','expiresAt']) || data.actorId !== actorIdForKey(data.publicKey) || !Array.isArray(data.scopes) || data.scopes.length < 1 || data.scopes.length > 2 || new Set(data.scopes).size !== data.scopes.length || data.scopes.some(scope => !['post.delete','report.read'].includes(scope)) || !Number.isFinite(Date.parse(data.expiresAt)) || Date.parse(data.expiresAt) <= Date.parse(event.issuedAt) || Date.parse(data.expiresAt) - Date.parse(event.issuedAt) > 30 * 86_400_000) fail('invalid_delegation');
      state.delegates[data.actorId] = structuredClone(data); break;
    }
    case 'delegation.revoke': if (!owner || !exact(data,['actorId']) || !actor(data.actorId)) fail('authority_denied'); delete state.delegates[data.actorId]; break;
    case 'post.create': {
      if (!member) fail('authority_denied');
      if (!exact(data,['text','parentId']) || !text(data.text,2000) || data.parentId !== null && (!uuid(data.parentId) || !Object.hasOwn(state.posts,data.parentId))) fail('invalid_post');
      if (Object.keys(state.posts).length >= 10_000) fail('capacity');
      state.posts[event.eventId] = { id: event.eventId, actorId: event.actorId, text: data.text, parentId: data.parentId, createdAt: event.issuedAt, createdSequence:event.sequence }; break;
    }
    case 'post.delete': {
      if (!exact(data,['postId','reason']) || !uuid(data.postId) || !text(data.reason,500) || !Object.hasOwn(state.posts,data.postId)) fail('invalid_post');
      if (state.posts[data.postId].actorId !== event.actorId && !admin && !scoped('post.delete')) fail('authority_denied');
      delete state.posts[data.postId]; break;
    }
    case 'resource.create': {
      if(!member)fail('authority_denied');
      if(!exact(data,['title','url','description'])||!text(data.title,120)||!resourceUrl(data.url)||!optionalText(data.description,2000))fail('invalid_resource');
      if(Object.keys(state.resources).length>=1000)fail('capacity');
      state.resources[event.eventId]={id:event.eventId,actorId:event.actorId,...data,createdAt:event.issuedAt,createdSequence:event.sequence};break;
    }
    case 'resource.delete': {
      if(!exact(data,['resourceId','reason'])||!uuid(data.resourceId)||!text(data.reason,500)||!Object.hasOwn(state.resources,data.resourceId))fail('invalid_resource');
      if(state.resources[data.resourceId].actorId!==event.actorId&&!admin)fail('authority_denied');
      delete state.resources[data.resourceId];break;
    }
    case 'event.create': {
      if(!member)fail('authority_denied');
      if(!exact(data,['title','description','startsAt','endsAt','location'])||!text(data.title,120)||!optionalText(data.description,2000)||!optionalText(data.location,300)||!timestamp(data.startsAt)||!timestamp(data.endsAt)||Date.parse(data.startsAt)<=authorityTime||Date.parse(data.startsAt)-Date.parse(event.issuedAt)>366*86_400_000||Date.parse(data.endsAt)<=Date.parse(data.startsAt)||Date.parse(data.endsAt)-Date.parse(data.startsAt)>31*86_400_000)fail('invalid_calendar_event');
      if(Object.keys(state.calendarEvents).length>=1000)fail('capacity');
      state.calendarEvents[event.eventId]={id:event.eventId,actorId:event.actorId,...data,createdAt:event.issuedAt,createdSequence:event.sequence,cancelledAt:null,cancellationReason:null,rsvps:{}};break;
    }
    case 'event.cancel': {
      if(!exact(data,['eventId','reason'])||!uuid(data.eventId)||!text(data.reason,500)||!Object.hasOwn(state.calendarEvents,data.eventId))fail('invalid_calendar_event');
      const item=state.calendarEvents[data.eventId];if(item.actorId!==event.actorId&&!admin)fail('authority_denied');
      if(item.cancelledAt)fail('event_cancelled');
      item.cancelledAt=event.issuedAt;item.cancellationReason=data.reason;break;
    }
    case 'event.rsvp': {
      if(!member)fail('authority_denied');
      if(!exact(data,['eventId','response'])||!uuid(data.eventId)||!['going','interested','not_going'].includes(data.response)||!Object.hasOwn(state.calendarEvents,data.eventId))fail('invalid_rsvp');
      const item=state.calendarEvents[data.eventId];if(item.cancelledAt||Date.parse(item.endsAt)<=authorityTime)fail('event_closed');
      item.rsvps[event.actorId]={response:data.response,updatedAt:event.issuedAt};break;
    }
    case 'poll.create': {
      if(!member)fail('authority_denied');
      if(!exact(data,['question','options','closesAt'])||!text(data.question,300)||!Array.isArray(data.options)||data.options.length<2||data.options.length>8||data.options.some(option=>!text(option,120))||new Set(data.options.map(option=>option.trim().toLowerCase())).size!==data.options.length||!timestamp(data.closesAt)||Date.parse(data.closesAt)<=authorityTime||Date.parse(data.closesAt)-Date.parse(event.issuedAt)>30*86_400_000)fail('invalid_poll');
      if(Object.keys(state.polls).length>=1000)fail('capacity');
      state.polls[event.eventId]={id:event.eventId,actorId:event.actorId,...data,createdAt:event.issuedAt,createdSequence:event.sequence,closedAt:null,closeReason:null,votes:{}};break;
    }
    case 'poll.vote': {
      if(!member)fail('authority_denied');
      if(!exact(data,['pollId','optionIndex'])||!uuid(data.pollId)||!Number.isInteger(data.optionIndex)||!Object.hasOwn(state.polls,data.pollId)||data.optionIndex<0||data.optionIndex>=state.polls[data.pollId].options.length)fail('invalid_vote');
      const item=state.polls[data.pollId];if(item.closedAt||Date.parse(item.closesAt)<=authorityTime)fail('poll_closed');
      item.votes[event.actorId]={optionIndex:data.optionIndex,updatedAt:event.issuedAt};break;
    }
    case 'poll.close': {
      if(!exact(data,['pollId','reason'])||!uuid(data.pollId)||!text(data.reason,500)||!Object.hasOwn(state.polls,data.pollId))fail('invalid_poll');
      const item=state.polls[data.pollId];if(item.actorId!==event.actorId&&!admin)fail('authority_denied');
      if(item.closedAt)fail('poll_closed');
      item.closedAt=event.issuedAt;item.closeReason=data.reason;break;
    }
    case 'report.create': {
      if (privateDataMissing) { if (!publicOnly) fail('private_report_missing'); break; }
      // Public-surface reporting needs no membership; the signed key does not
      // receive publishing or moderation authority as a side effect.
      const oldShape=exact(data,['postId','reviewedText','reason','shareWithModerators']);
      if(!oldShape&&!exact(data,['targetKind','targetId','reviewedText','reason','shareWithModerators']))fail('invalid_report');
      const targetKind=oldShape?'post':data.targetKind,targetId=oldShape?data.postId:data.targetId;
      if(!['post','resource','event','poll'].includes(targetKind)||!uuid(targetId)||!text(data.reason,500)||data.shareWithModerators!==true||data.reviewedText!==reportEvidence(state,targetKind,targetId))fail('invalid_report');
      if (Object.keys(state.reports).length >= 1000) fail('capacity');
      state.reports[event.eventId] = { id: event.eventId, ...data, targetKind,targetId,reporter: event.actorId, status: 'received', history: [] }; break;
    }
    case 'report.review': {
      if (!admin) fail('authority_denied');
      if (privateDataMissing) { if (!publicOnly) fail('private_report_missing'); break; }
      if (!exact(data,['reportId','status','reason']) || !uuid(data.reportId) || !['reviewing','resolved'].includes(data.status) || !text(data.reason,500) || !Object.hasOwn(state.reports,data.reportId)) fail('invalid_report');
      state.reports[data.reportId].status = data.status;
      state.reports[data.reportId].history.push({ actorId: event.actorId, status: data.status, reason: data.reason, at: event.issuedAt }); break;
    }
    case 'host.freeze': if (!owner || !exact(data,['destination']) || !endpoint(data.destination) || data.destination === state.host) fail('authority_denied'); state.frozen = true; state.destination = data.destination; break;
    case 'host.resume': if (!owner || !previous.frozen || !importing || !exact(data,['host']) || data.host !== previous.destination) fail('authority_denied'); state.host = data.host; state.frozen = false; delete state.destination; break;
    default: fail('unsupported_action');
  }
  if (state.events.length >= 20_000) fail('capacity');
  state.sequence = event.sequence; state.head = digest; state.journalBytes=journalBytes;state.eventIds.push(event.eventId); state.events.push(compact); return state;
}
export function publicView(state) {
  return { protocol: PROTOCOL, proofs: state.events.map(value=>value.split('~')[0]), id: state.id, name: state.name, visibility: state.visibility, enrollment: state.enrollment, host: state.host, owner: state.owner,
    sequence: state.sequence, head: state.head, frozen: state.frozen, destination: state.destination ?? null, createdAt:state.createdAt,posts: Object.values(state.posts),resources:Object.values(state.resources),calendarEvents:Object.values(state.calendarEvents),polls:Object.values(state.polls),
    members: Object.entries(state.members).map(([actorId,member])=>({actorId,role:member.role,displayName:member.displayName??null})),
    pendingMembers:Object.values(state.pendingMembers).map(({actorId,displayName,requestedAt})=>({actorId,displayName,requestedAt})),
    delegates: Object.values(state.delegates).map(({actorId,scopes,expiresAt})=>({actorId,scopes,expiresAt})) };
}
