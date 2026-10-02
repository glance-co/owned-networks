// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createIdentity,applyEvent,nextEvent,replay,publicView,reportEvidence } from '../src/index.mjs';
const setup=(enrollment='open')=>{const owner=createIdentity(),member=createIdentity(),outsider=createIdentity();let state=applyEvent(null,nextEvent(owner,null,'network.create',{name:'Public community',visibility:'public',host:'https://community.example',enrollment,displayName:'Owner'}));const apply=(identity,action,data,options={})=>state=applyEvent(state,nextEvent(identity,state,action,data),options);return {owner,member,outsider,apply,get state(){return state;}};};

test('named approval requests and owner-scoped roles never confer founder or self-approval authority',()=>{
  const community=setup('approval'),{owner,member,outsider,apply}=community;
  apply(member,'member.request',{displayName:'A community member'});
  assert.equal(publicView(community.state).pendingMembers[0].displayName,'A community member');
  assert.throws(()=>apply(member,'member.approve',{actorId:member.actorId,role:'administrator'}),/authority_denied/);
  assert.throws(()=>apply(outsider,'member.profile',{displayName:'Owner'}),/authority_denied/);
  apply(owner,'member.approve',{actorId:member.actorId,role:'member'});
  assert.equal(community.state.members[member.actorId].displayName,'A community member');
  apply(member,'member.profile',{displayName:'Renamed member'});
  assert.throws(()=>apply(member,'member.role',{actorId:member.actorId,role:'administrator'}),/authority_denied/);
  apply(owner,'member.role',{actorId:member.actorId,role:'administrator'});
  assert.throws(()=>apply(member,'owner.transfer',{actorId:member.actorId}),/authority_denied/);
  apply(owner,'member.role',{actorId:member.actorId,role:'member'});
  apply(owner,'member.remove',{actorId:member.actorId});
  assert.throws(()=>apply(member,'member.request',{displayName:'Removed member'}),/authority_denied/);
  assert.deepEqual(replay(community.state.events),community.state);
});

test('resources, events, public RSVP and advisory polls survive portable replay with exact report consent',()=>{
  const community=setup(),{owner,member,outsider,apply}=community;
  apply(member,'member.join',{displayName:'Neighbor'});
  apply(member,'resource.create',{title:'Shared handbook',url:'https://example.org/handbook',description:'Read before the gathering'});
  const resourceId=Object.keys(community.state.resources)[0];
  assert.throws(()=>apply(outsider,'resource.delete',{resourceId,reason:'No rights'}),/authority_denied/);
  assert.throws(()=>apply(member,'resource.create',{title:'Unsafe URL',url:'javascript:alert(1)',description:''}),/invalid_resource/);
  apply(member,'event.create',{title:'Community gathering',description:'Bring ideas',startsAt:new Date(Date.now()+3600000).toISOString(),endsAt:new Date(Date.now()+7200000).toISOString(),location:'Library'});
  const eventId=Object.keys(community.state.calendarEvents)[0];
  apply(owner,'event.rsvp',{eventId,response:'going'});apply(owner,'event.rsvp',{eventId,response:'interested'});
  assert.deepEqual(Object.values(community.state.calendarEvents[eventId].rsvps).map(row=>row.response),['interested']);
  apply(owner,'poll.create',{question:'Preferred day? (advisory)',options:['Saturday','Sunday'],closesAt:new Date(Date.now()+3600000).toISOString()});
  const pollId=Object.keys(community.state.polls)[0];
  apply(member,'poll.vote',{pollId,optionIndex:0});apply(member,'poll.vote',{pollId,optionIndex:1});
  assert.deepEqual(Object.values(community.state.polls[pollId].votes).map(row=>row.optionIndex),[1]);
  assert.throws(()=>apply(outsider,'poll.vote',{pollId,optionIndex:0}),/authority_denied/);
  assert.throws(()=>apply(owner,'poll.create',{question:'Duplicate choices',options:['Same',' same '],closesAt:new Date(Date.now()+3600000).toISOString()}),/invalid_poll/);
  for(const [targetKind,targetId] of [['resource',resourceId],['event',eventId],['poll',pollId]]){
    assert.throws(()=>apply(outsider,'report.create',{targetKind,targetId,reviewedText:'Unreviewed',reason:'Please review',shareWithModerators:true}),/invalid_report/);
    apply(outsider,'report.create',{targetKind,targetId,reviewedText:reportEvidence(community.state,targetKind,targetId),reason:'Please review',shareWithModerators:true});
  }
  const view=publicView(community.state);assert.equal('reports' in view,false);assert.equal(view.proofs.some(proof=>proof.includes('~')),false);
  apply(owner,'poll.close',{pollId,reason:'Advisory discussion ended'});assert.throws(()=>apply(member,'poll.vote',{pollId,optionIndex:0}),/poll_closed/);
  apply(member,'event.cancel',{eventId,reason:'Venue unavailable'});assert.throws(()=>apply(owner,'event.rsvp',{eventId,response:'going'}),/event_closed/);
  apply(member,'resource.delete',{resourceId,reason:'Outdated'});assert.equal(Object.keys(community.state.reports).length,3,'consented evidence survives source removal');
  assert.deepEqual(replay(community.state.events),community.state);
});

test('admission clock fences backdated votes and RSVPs while historical replay stays deterministic',()=>{
  const community=setup(),{owner,apply}=community,baseline=Date.now();
  apply(owner,'poll.create',{question:'Time bounded',options:['Yes','No'],closesAt:new Date(baseline+1000).toISOString()});const pollId=Object.keys(community.state.polls)[0];
  const vote=nextEvent(owner,community.state,'poll.vote',{pollId,optionIndex:0},new Date(baseline+500));
  assert.throws(()=>applyEvent(community.state,vote,{admissionNow:baseline+2000}),/poll_closed/);
  const historical=applyEvent(community.state,vote,{admissionNow:baseline+500});assert.deepEqual(replay(historical.events),historical);
  apply(owner,'event.create',{title:'Ending soon',description:'',startsAt:new Date(baseline+1000).toISOString(),endsAt:new Date(baseline+2000).toISOString(),location:''});const eventId=Object.keys(community.state.calendarEvents)[0];
  const rsvp=nextEvent(owner,community.state,'event.rsvp',{eventId,response:'going'},new Date(baseline+1500));
  assert.throws(()=>applyEvent(community.state,rsvp,{admissionNow:baseline+3000}),/event_closed/);
});

test('future-skewed signed commands cannot persist a history that fails historical replay',()=>{
  const community=setup(),{owner,apply}=community,baseline=Date.now();
  const future=new Date(baseline+50000),close=new Date(baseline+30000).toISOString();
  const earlyPoll=nextEvent(owner,community.state,'poll.create',{question:'Must still be valid at signed time',options:['Yes','No'],closesAt:close},future);
  assert.throws(()=>applyEvent(community.state,earlyPoll,{admissionNow:baseline}),/invalid_poll/);
  const earlyEvent=nextEvent(owner,community.state,'event.create',{title:'Must not start before signed time',description:'',startsAt:close,endsAt:new Date(baseline+60000).toISOString(),location:''},future);
  assert.throws(()=>applyEvent(community.state,earlyEvent,{admissionNow:baseline}),/invalid_calendar_event/);
  apply(owner,'poll.create',{question:'Closing within request skew',options:['One','Two'],closesAt:close});
  const pollId=Object.keys(community.state.polls)[0];
  const lateVote=nextEvent(owner,community.state,'poll.vote',{pollId,optionIndex:0},future);
  assert.throws(()=>applyEvent(community.state,lateVote,{admissionNow:baseline}),/poll_closed/);
});

test('ordinary journal saturation preserves reserved moderation and initial handoff within transport bounds',()=>{
  const community=setup(),{owner,outsider,apply}=community,delegate=createIdentity();
  apply(owner,'post.create',{text:'Public evidence '.repeat(120),parentId:null});const postId=Object.keys(community.state.posts)[0];
  apply(owner,'delegation.grant',{actorId:delegate.actorId,publicKey:delegate.publicJwk,scopes:['report.read'],expiresAt:new Date(Date.now()+3600000).toISOString()});
  let full=false;
  for(let index=0;index<1000;index++)try{apply(outsider,'report.create',{postId,reviewedText:community.state.posts[postId].text,reason:'Public report rationale '.repeat(20),shareWithModerators:true});}catch(error){assert.match(error.message,/capacity/);full=true;break;}
  assert.equal(full,true);try{apply(owner,'post.create',{text:'x'.repeat(2000),parentId:null});}catch(error){assert.match(error.message,/capacity/);}
  assert.throws(()=>apply(owner,'post.create',{text:'x'.repeat(2000),parentId:null}),/capacity/);
  apply(owner,'delegation.revoke',{actorId:delegate.actorId});
  apply(owner,'report.review',{reportId:Object.keys(community.state.reports)[0],status:'resolved',reason:'Owner retains review capability at the ordinary limit'});
  apply(owner,'post.delete',{postId,reason:'Owner retains moderation capability'});
  apply(owner,'host.freeze',{destination:'https://second.example'});
  const resume=nextEvent(owner,community.state,'host.resume',{host:'https://second.example'});
  assert.ok(Buffer.byteLength(JSON.stringify({protocol:'glance-owned-network/1',events:community.state.events,resume}))<4_000_000);
  const resumed=applyEvent(community.state,resume,{importing:true});assert.ok(Buffer.byteLength(JSON.stringify(publicView(resumed)))<4_000_000);assert.equal(resumed.frozen,false);
});
