// SPDX-License-Identifier: Apache-2.0
import { Pool } from 'pg';
import { createCipheriv,createDecipheriv,hkdfSync,randomBytes } from 'node:crypto';
import { ProtocolError } from '../../v3-network-protocol/src/index.mjs';
import { replayJournal } from './replay.mjs';

function journalCodec(storageKey,origin) {
  if(typeof storageKey!=='string'||Buffer.byteLength(storageKey)<32)throw new Error('network_storage_key_required');
  const key=Buffer.from(hkdfSync('sha256',Buffer.from(storageKey),Buffer.from('glance-owned-network/storage/1'),Buffer.from('journal-at-rest'),32));
  const additionalData=id=>Buffer.from(`${origin}\0${id}`);
  return {
    encrypt(state){const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(additionalData(state.id));const ciphertext=Buffer.concat([cipher.update(JSON.stringify(state.events),'utf8'),cipher.final()]);return ['1',iv.toString('base64url'),cipher.getAuthTag().toString('base64url'),ciphertext.toString('base64url')].join('.');},
    decrypt(id,value){const [version,nonce,tag,encrypted,...extra]=value.split('.');if(version!=='1'||extra.length||!nonce||!tag||!encrypted)throw new Error('invalid_stored_journal');const iv=Buffer.from(nonce,'base64url'),authTag=Buffer.from(tag,'base64url');if(iv.length!==12||authTag.length!==16)throw new Error('invalid_stored_journal');const decipher=createDecipheriv('aes-256-gcm',key,iv);decipher.setAAD(additionalData(id));decipher.setAuthTag(authTag);const decoded=Buffer.concat([decipher.update(Buffer.from(encrypted,'base64url')),decipher.final()]);try{return JSON.parse(decoded.toString('utf8'));}finally{decoded.fill(0);}},
    destroy(){key.fill(0);},
  };
}

// Each mutation obtains one connection and a transaction-scoped network lock.
// No authority, freeze state, rate budget or acknowledgement lives in an API
// process cache. Committed PostgreSQL WAL is the acknowledgement boundary.
export async function createPostgresNetworkStore({connectionString,origin,storageKey,pool:providedPool,maxConnections=5}) {
  if(typeof origin!=='string'||new URL(origin).origin!==origin)throw new Error('invalid_network_origin');
  const codec=journalCodec(storageKey,origin);
  const pool=providedPool??new Pool({connectionString,max:maxConnections,connectionTimeoutMillis:5000,idleTimeoutMillis:30000,statement_timeout:10000,application_name:'glance-owned-network'});
  // Unhandled idle-client errors must not crash the serving process or print
  // connection details. The next operation returns service_unavailable.
  if(!providedPool)pool.on('error',()=>{});
  const decodeRow=async row=>{
    if(!row)return null;
    const state=await replayJournal(codec.decrypt(row.id,row.journalCiphertext));
    if(state.id!==row.id||state.host!==origin||state.sequence!==row.sequence||state.head!==row.head||state.frozen!==row.frozen||(state.destination??null)!==row.destination)throw new Error('stored_network_integrity_failed');
    return state;
  };
  let closed=false;
  const store={
    kind:'postgres',durableHandoff:true,
    async health(){
      if(closed)throw new Error('store_closed');
      await pool.query('SELECT "id","host","sequence","head","frozen","destination","journalCiphertext","createdAt","updatedAt" FROM "OwnedNetwork" LIMIT 0');await pool.query('SELECT "key","windowAt","count","expiresAt" FROM "OwnedNetworkRate" LIMIT 0');
      const constraints=await pool.query(`SELECT conname,contype,convalidated,pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid IN ('"OwnedNetwork"'::regclass,'"OwnedNetworkRate"'::regclass)`);
      const expected={OwnedNetwork_pkey:['p','PRIMARY KEY (host, id)'],OwnedNetworkRate_pkey:['p','PRIMARY KEY (key)'],OwnedNetwork_sequence_positive:['c','CHECK ((sequence > 0))'],OwnedNetworkRate_count_positive:['c','CHECK ((count > 0))'],OwnedNetwork_frozen_destination:['c','CHECK (((frozen AND (destination IS NOT NULL) AND ((destination)::text <> (host)::text)) OR ((NOT frozen) AND (destination IS NULL))))']};
      const normalized=value=>value.replace(/["\s]/g,'');
      for(const [name,[type,definition]] of Object.entries(expected)){const actual=constraints.rows.find(row=>row.conname===name);if(!actual?.convalidated||actual.contype!==type||normalized(actual.definition)!==normalized(definition))throw new Error('network_schema_unready');}
      const indexes=await pool.query(`SELECT i.indisvalid,i.indisunique,i.indnkeyatts,i.indnatts,i.indpred IS NULL AS unconditional,pg_get_indexdef(i.indexrelid,1,true) AS column,am.amname,t.relname AS table FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_class t ON t.oid=i.indrelid JOIN pg_am am ON am.oid=c.relam WHERE i.indexrelid=to_regclass('"OwnedNetworkRate_expiresAt_idx"')`);
      const index=indexes.rows[0];if(index?.indisvalid!==true||index.indisunique!==false||index.indnkeyatts!==1||index.indnatts!==1||!index.unconditional||index.column.replaceAll('"','')!=='expiresAt'||index.amname!=='btree'||index.table!=='OwnedNetworkRate')throw new Error('network_schema_unready');
      const columns=await pool.query(`SELECT table_name,column_name,data_type,udt_name,is_nullable,character_maximum_length,datetime_precision FROM information_schema.columns WHERE table_schema=current_schema() AND table_name IN ('OwnedNetwork','OwnedNetworkRate')`);
      const shape={OwnedNetwork:{host:['varchar','NO',2048],id:['uuid','NO'],sequence:['int4','NO'],head:['varchar','NO',43],frozen:['bool','NO'],destination:['varchar','YES',2048],journalCiphertext:['text','NO'],createdAt:['timestamptz','NO',null,3],updatedAt:['timestamptz','NO',null,3]},OwnedNetworkRate:{key:['varchar','NO',64],windowAt:['timestamptz','NO',null,3],count:['int4','NO'],expiresAt:['timestamptz','NO',null,3]}};
      for(const [table,fields] of Object.entries(shape))for(const [column,[type,nullable,length,precision]] of Object.entries(fields)){const actual=columns.rows.find(row=>row.table_name===table&&row.column_name===column);if(!actual||actual.udt_name!==type||actual.is_nullable!==nullable||length&&actual.character_maximum_length!==length||precision&&actual.datetime_precision!==precision)throw new Error('network_schema_unready');}
      const existing=await pool.query('SELECT * FROM "OwnedNetwork" WHERE "host"=$1 ORDER BY "updatedAt" DESC LIMIT 1',[origin]);if(existing.rows[0])await decodeRow(existing.rows[0]);
      return {store:'postgres',durableHandoff:true};
    },
    async get(id){const result=await pool.query('SELECT * FROM "OwnedNetwork" WHERE "host"=$1 AND "id"=$2',[origin,id]);return decodeRow(result.rows[0]);},
    async list({afterId='',limit=20}={}){
      const metadata=await pool.query('SELECT "id",octet_length("journalCiphertext") AS bytes FROM "OwnedNetwork" WHERE "host"=$1 AND "id"::text>$2 ORDER BY "id" ASC LIMIT $3',[origin,afterId,limit]);
      const selected=[];let bytes=0;
      for(const row of metadata.rows){if(selected.length&&(selected.length>=2||bytes+row.bytes>3_000_000))break;selected.push(row.id);bytes+=row.bytes;}
      if(!selected.length)return {items:[],hasMore:false};
      const result=await pool.query('SELECT * FROM "OwnedNetwork" WHERE "host"=$1 AND "id"=ANY($2::uuid[]) ORDER BY "id" ASC',[origin,selected]);
      return {items:await Promise.all(result.rows.map(decodeRow)),hasMore:metadata.rows.length>selected.length};
    },
    async transaction(id,work){
      const client=await pool.connect();
      try{
        await client.query('BEGIN');
        await client.query("SET LOCAL lock_timeout='5s'");
        await client.query("SET LOCAL statement_timeout='10s'");
        await client.query("SET LOCAL idle_in_transaction_session_timeout='15s'");
        await client.query("SET LOCAL synchronous_commit='on'");
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`glance-owned-network:${origin}:${id}`]);
        const row=await client.query('SELECT * FROM "OwnedNetwork" WHERE "host"=$1 AND "id"=$2 FOR UPDATE',[origin,id]);
        const previous=await decodeRow(row.rows[0]),result=await work(previous);
        if(result.state){
          const state=result.state;if(state.id!==id||state.host!==origin)throw new ProtocolError('wrong_host');
          await client.query('INSERT INTO "OwnedNetwork" ("host","id","sequence","head","frozen","destination","journalCiphertext","createdAt","updatedAt") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP) ON CONFLICT ("host","id") DO UPDATE SET "sequence"=EXCLUDED."sequence","head"=EXCLUDED."head","frozen"=EXCLUDED."frozen","destination"=EXCLUDED."destination","journalCiphertext"=EXCLUDED."journalCiphertext","updatedAt"=CURRENT_TIMESTAMP',[origin,id,state.sequence,state.head,state.frozen,state.destination??null,codec.encrypt(state),new Date(state.createdAt)]);
        }
        await client.query('COMMIT');return result.result;
      }catch(error){try{await client.query('ROLLBACK');}catch{/* original failure remains */}throw error;}finally{client.release();}
    },
    async takeRate(key,limit,windowMs=60000){
      if(!/^[a-f0-9]{64}$/.test(key))throw new Error('invalid_rate_key');
      // Database time makes this budget consistent across replicas with skewed
      // clocks. Keys are hashed outside this store; source IPs are not retained.
      const result=await pool.query(`INSERT INTO "OwnedNetworkRate" ("key","windowAt","count","expiresAt") VALUES ($1,to_timestamp(floor(extract(epoch FROM clock_timestamp())*1000/$2::double precision)*$2::double precision/1000),1,clock_timestamp()+($2::double precision*interval '1 millisecond')) ON CONFLICT ("key") DO UPDATE SET "count"=CASE WHEN "OwnedNetworkRate"."windowAt"=EXCLUDED."windowAt" THEN LEAST("OwnedNetworkRate"."count"+1,1000000) ELSE 1 END,"windowAt"=EXCLUDED."windowAt","expiresAt"=EXCLUDED."expiresAt" RETURNING "count"`,[key,windowMs]);
      if(randomBytes(1)[0]===0)await pool.query('DELETE FROM "OwnedNetworkRate" WHERE "key" IN (SELECT "key" FROM "OwnedNetworkRate" WHERE "expiresAt"<clock_timestamp() LIMIT 500)');
      return result.rows[0].count<=limit;
    },
    async close(){if(closed)return;closed=true;if(!providedPool)await pool.end();codec.destroy();},
  };
  const checkHealth=store.health.bind(store);let healthyUntil=0,healthPending=null;
  store.health=async()=>{
    if(closed)throw new Error('store_closed');
    if(Date.now()<healthyUntil)return {store:'postgres',durableHandoff:true};
    if(!healthPending)healthPending=checkHealth().then(value=>{healthyUntil=Date.now()+5000;return value;}).finally(()=>{healthPending=null;});
    return healthPending;
  };
  try{await store.health();return store;}catch(error){await store.close();throw error;}
}
